package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

const (
	domainsDir     = "./domains_split"
	maxParallel    = 4
	defaultThreads = 100
)

type fileProgress struct {
	totalDomains int
	domainsDone  int
	keysFound    int
	startTime    time.Time
	filename     string
}

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose output to show currently processed files")
	threads := flag.Int("threads", defaultThreads, "Number of threads to use for processing")
	flag.Parse()

	clearScreen()

	files, err := os.ReadDir(domainsDir)
	if err != nil {
		color.Red("Erreur lors de la lecture de %s : %v\n", domainsDir, err)
		os.Exit(1)
	}

	var txtFiles []os.DirEntry
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".txt" {
			txtFiles = append(txtFiles, file)
		}
	}

	sort.Slice(txtFiles, func(i, j int) bool {
		numI := extractFileNumber(txtFiles[i].Name())
		numJ := extractFileNumber(txtFiles[j].Name())
		return numI < numJ
	})

	var totalFiles int32 = int32(len(txtFiles))
	var completedFiles int32
	var totalKeysFound int32
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxParallel)
	progressInfo := make(map[string]*fileProgress)
	barsMutex := sync.Mutex{}
	startTime := time.Now()

	stopDisplayChan := make(chan struct{})
	go displayProgressDynamic(&barsMutex, progressInfo, &completedFiles, &totalFiles, &totalKeysFound, startTime, *verbose, stopDisplayChan)

	fileChan := make(chan string, len(txtFiles))
	for _, file := range txtFiles {
		fileChan <- filepath.Join(domainsDir, file.Name())
	}
	close(fileChan)

	for i := 0; i < maxParallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filename := range fileChan {
				semaphore <- struct{}{}
				processFile(filename, &barsMutex, progressInfo, &completedFiles, &totalKeysFound, *verbose, *threads)
				<-semaphore
			}
		}()
	}

	wg.Wait()
	close(stopDisplayChan)

	clearScreen()
	displayFinal(&barsMutex, progressInfo, completedFiles, totalFiles, totalKeysFound, startTime)
}

func processFile(filename string, barsMutex *sync.Mutex, progressInfo map[string]*fileProgress, completedFiles, totalKeysFound *int32, verbose bool, threads int) {
	baseName := filepath.Base(filename)
	totalDomains := getDomainCount(filename)

	barsMutex.Lock()
	progressInfo[filename] = &fileProgress{
		totalDomains: totalDomains,
		domainsDone:  0,
		keysFound:    0,
		startTime:    time.Now(),
		filename:     baseName,
	}
	barsMutex.Unlock()

	cmd := exec.Command("./main", "-domains", filename, "-threads", strconv.Itoa(threads))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		color.Red("Erreur lors de la création du pipe pour %s : %v\n", baseName, err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		color.Red("Erreur lors de la création du pipe stderr pour %s : %v\n", baseName, err)
		return
	}

	color.Cyan("Lancement de la commande pour %s : %v\n", baseName, cmd.Args)

	if err := cmd.Start(); err != nil {
		color.Red("Erreur lors du démarrage de %s : %v\n", baseName, err)
		return
	}

	statusRegex := regexp.MustCompile(`\[STATUS\] Domains: (\d+)`)
	progressRegex := regexp.MustCompile(`\[PROGRESS\] (\d+)/(\d+) domains processed`)
	foundRegex := regexp.MustCompile(`\[FOUND\]`)
	completeRegex := regexp.MustCompile(`\[COMPLETE\] .* Total URLs scanned: (\d+), Total keys found: (\d+)`)

	doneDomains := 0
	keysFound := 0

	var logWg sync.WaitGroup
	logWg.Add(2)

	doneChan := make(chan struct{})

	go func() {
		defer logWg.Done()
		reader := bufio.NewReader(stdout)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					color.Red("Erreur lors de la lecture de stdout pour %s : %v\n", baseName, err)
				}
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			barsMutex.Lock()
			updateProgress(line, statusRegex, progressRegex, foundRegex, completeRegex, progressInfo[filename], totalDomains, &doneDomains, &keysFound, totalKeysFound)
			barsMutex.Unlock()
		}
	}()

	go func() {
		defer logWg.Done()
		reader := bufio.NewReader(stderr)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					color.Red("Erreur lors de la lecture de stderr pour %s : %v\n", baseName, err)
				}
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			barsMutex.Lock()
			updateProgress(line, statusRegex, progressRegex, foundRegex, completeRegex, progressInfo[filename], totalDomains, &doneDomains, &keysFound, totalKeysFound)
			barsMutex.Unlock()
		}
	}()

	go func() {
		err := cmd.Wait()
		barsMutex.Lock()
		if err != nil {
			color.Red("Erreur lors de l'exécution de %s : %v\n", baseName, err)
		}
		if progressInfo[filename].domainsDone >= progressInfo[filename].totalDomains {
			progressInfo[filename].domainsDone = progressInfo[filename].totalDomains
		}
		atomic.AddInt32(completedFiles, 1)
		barsMutex.Unlock()
		close(doneChan)
	}()

	logWg.Wait()
	<-doneChan
}

func clearScreen() {
	if _, err := fmt.Print("\033[H\033[2J"); err != nil {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		_ = cmd.Run()
	}
}

func moveCursor(row, col int) {
	fmt.Printf("\033[%d;%dH", row, col)
}

func extractFileNumber(filename string) int {
	re := regexp.MustCompile(`domains_part_(\d+)\.txt`)
	matches := re.FindStringSubmatch(filename)
	if len(matches) > 1 {
		num, err := strconv.Atoi(matches[1])
		if err == nil {
			return num
		}
	}
	return 999999
}

func updateProgress(line string, statusRegex, progressRegex, foundRegex, completeRegex *regexp.Regexp, fp *fileProgress, totalDomains int, doneDomains, keysFound *int, totalKeysFound *int32) {
	if matches := statusRegex.FindStringSubmatch(line); len(matches) > 1 {
		*doneDomains = atoi(matches[1])
		if *doneDomains >= totalDomains {
			*doneDomains = totalDomains
			fp.domainsDone = totalDomains
		} else {
			fp.domainsDone = *doneDomains
		}
	}

	if matches := progressRegex.FindStringSubmatch(line); len(matches) > 2 {
		*doneDomains = atoi(matches[1])
		if *doneDomains >= totalDomains {
			*doneDomains = totalDomains
			fp.domainsDone = totalDomains
		} else {
			fp.domainsDone = *doneDomains
		}
	}

	if foundRegex.MatchString(line) {
		*keysFound++
		fp.keysFound = *keysFound
		atomic.AddInt32(totalKeysFound, 1)
	}

	if matches := completeRegex.FindStringSubmatch(line); len(matches) > 2 {
		*doneDomains = totalDomains
		fp.domainsDone = totalDomains
		*keysFound = atoi(matches[2])
		fp.keysFound = *keysFound
		atomic.AddInt32(totalKeysFound, int32(*keysFound))
	}
}

func displayProgressDynamic(barsMutex *sync.Mutex, progressInfo map[string]*fileProgress, completedFiles, totalFiles, totalKeysFound *int32, startTime time.Time, verbose bool, stopChan chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	lastActiveFiles := 0
	lineCount := 3

	blue := color.New(color.FgBlue, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	for {
		select {
		case <-ticker.C:
			barsMutex.Lock()

			clearLines(lineCount)
			moveCursor(1, 1)

			completed := atomic.LoadInt32(completedFiles)
			total := atomic.LoadInt32(totalFiles)
			keys := atomic.LoadInt32(totalKeysFound)
			progress := float64(completed) / float64(total) * 100
			elapsed := time.Since(startTime).Round(time.Second)

			lineCount = 5

			fmt.Println(cyan("FICHIERS EN COURS DE TRAITEMENT:"))
			lineCount++

			var activeFiles []string
			for filename, fp := range progressInfo {
				if fp.domainsDone < fp.totalDomains {
					activeFiles = append(activeFiles, filename)
				}
			}

			sort.Slice(activeFiles, func(i, j int) bool {
				return extractFileNumber(filepath.Base(activeFiles[i])) < extractFileNumber(filepath.Base(activeFiles[j]))
			})

			if len(activeFiles) > 0 {
				for _, filename := range activeFiles {
					fp := progressInfo[filename]
					percent := 0.0
					if fp.totalDomains > 0 {
						percent = float64(fp.domainsDone) / float64(fp.totalDomains) * 100
					}

					shortName := filepath.Base(fp.filename)
					if len(shortName) > 18 {
						shortName = shortName[:15] + "..."
					}

					fmt.Printf("  %-18s : %s (%.1f%%) | %s\n",
						green(shortName),
						yellow(fmt.Sprintf("%d/%d domaines", fp.domainsDone, fp.totalDomains)),
						percent,
						yellow(fmt.Sprintf("%d clés", fp.keysFound)))
					lineCount++
				}
			} else {
				fmt.Println("  Aucun fichier en cours de traitement")
				lineCount++
			}

			fmt.Printf("%s - %s écoulé\n", blue("ANALYSE DE DOMAINES"), elapsed)
			fmt.Printf("%s %d/%d fichiers traités (%.1f%%) | %s\n",
				green("[GLOBAL]"), completed, total, progress, yellow(fmt.Sprintf("%d clés trouvées", keys)))

			barWidth := 50
			completedWidth := int(float64(barWidth) * float64(completed) / float64(total))
			fmt.Print("[")
			for i := 0; i < barWidth; i++ {
				if i < completedWidth {
					fmt.Print(green("="))
				} else if i == completedWidth && completed < total {
					fmt.Print(cyan(">"))
				} else {
					fmt.Print(" ")
				}
			}
			fmt.Printf("] %s\n\n", yellow(fmt.Sprintf("%.1f%%", progress)))

			lastActiveFiles = len(activeFiles)
			if lastActiveFiles == 0 {
				lastActiveFiles = 1
			}

			barsMutex.Unlock()

		case <-stopChan:
			return
		}
	}
}

func clearLines(count int) {
	moveCursor(1, 1)
	fmt.Print("\033[2J")
	moveCursor(1, 1)
}

func displayFinal(barsMutex *sync.Mutex, progressInfo map[string]*fileProgress, completedFiles, totalFiles, totalKeysFound int32, startTime time.Time) {
	barsMutex.Lock()
	progress := float64(completedFiles) / float64(totalFiles) * 100

	blue := color.New(color.FgBlue, color.Bold).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("%s - %s écoulé\n\n", blue("ANALYSE TERMINÉE"), time.Since(startTime).Round(time.Second))
	fmt.Printf("%s %d/%d fichiers traités (%.1f%%) | %s\n\n",
		green("[FINAL]"), completedFiles, totalFiles, progress, yellow(fmt.Sprintf("%d clés trouvées", totalKeysFound)))

	fmt.Println(green("RÉSUMÉ PAR FICHIER:"))
	fmt.Println(yellow("-----------------------------------------------------------"))
	fmt.Printf("%-20s | %-15s | %-7s | %s\n", green("FICHIER"), green("DOMAINES"), green("CLÉS"), green("DURÉE"))
	fmt.Println(yellow("-----------------------------------------------------------"))

	var fileNames []string
	for name := range progressInfo {
		fileNames = append(fileNames, name)
	}

	sort.Slice(fileNames, func(i, j int) bool {
		return extractFileNumber(filepath.Base(fileNames[i])) < extractFileNumber(filepath.Base(fileNames[j]))
	})

	for _, name := range fileNames {
		fp := progressInfo[name]
		elapsed := time.Since(fp.startTime).Round(time.Second)

		shortName := filepath.Base(fp.filename)
		if len(shortName) > 20 {
			shortName = shortName[:17] + "..."
		}

		fmt.Printf("%-20s | %s | %s | %s\n",
			green(shortName),
			yellow(fmt.Sprintf("%5d/%-7d", fp.domainsDone, fp.totalDomains)),
			yellow(fmt.Sprintf("%7d", fp.keysFound)),
			yellow(fmt.Sprintf("%s", elapsed)))
	}
	fmt.Println(yellow("-----------------------------------------------------------"))
	fmt.Println("\n%s", blue("Toutes les analyses sont terminées !"))
	barsMutex.Unlock()
}

func getDomainCount(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		return 10000
	}
	defer file.Close()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	if count == 0 {
		return 10000
	}
	return count
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
