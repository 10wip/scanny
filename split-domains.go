package main

import (
    "bufio"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/fatih/color"
)

func main() {
    titleColor := color.New(color.FgCyan, color.Bold)
    successColor := color.New(color.FgGreen)
    errorColor := color.New(color.FgRed)
    promptColor := color.New(color.FgYellow)

    for {
        titleColor.Println("\n=== CLI de Gestion des Domaines & Clés ===")
        fmt.Println("1. Diviser le fichier de domaines")
        fmt.Println("2. Supprimer le répertoire domains_split")
        fmt.Println("3. Combiner les clés AWS")
        fmt.Println("4. Combiner les clés régulières")
        fmt.Println("5. Supprimer les fichiers de clés (.txt)")
        fmt.Println("6. Supprimer le répertoire dist")
        fmt.Println("7. Quitter")
        promptColor.Print("\nSélectionnez une option (1-7) : ")

        var choice string
        fmt.Scanln(&choice)

        switch choice {
        case "1":
            splitDomains(errorColor, successColor, promptColor)
        case "2":
            deleteDomainsSplit(errorColor, successColor)
        case "3":
            combineAWSKeys(errorColor, successColor)
        case "4":
            combineRegularKeys(errorColor, successColor)
        case "5":
            deleteKeys(errorColor, successColor, promptColor)
        case "6":
            deleteDist(errorColor, successColor, promptColor)
        case "7":
            successColor.Println("Quitter le programme...")
            return
        default:
            errorColor.Println("Option invalide. Veuillez sélectionner 1-7.")
        }
    }
}

func splitDomains(errorColor, successColor, promptColor *color.Color) {
    inputFile := "domains.txt"
    outputDir := "./domains_split"
    maxLines := 10000
    if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
        promptColor.Print("Supprimer le répertoire domains_split existant ? [O/n] : ")
        var response string
        fmt.Scanln(&response)
        response = strings.ToLower(response)
        if response == "" || response == "o" {
            if err := os.RemoveAll(outputDir); err != nil {
                errorColor.Printf("Erreur lors de la suppression de %s : %v\n", outputDir, err)
                return
            }
            successColor.Println("Répertoire domains_split existant supprimé")
        }
    }

    err := os.MkdirAll(outputDir, 0755)
    if err != nil {
        errorColor.Printf("Erreur lors de la création du répertoire %s : %v\n", outputDir, err)
        return
    }

    file, err := os.Open(inputFile)
    if err != nil {
        errorColor.Printf("Erreur lors de l'ouverture de %s : %v\n", inputFile, err)
        return
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    fileIndex := 0
    lineCount := 0
    var writer *bufio.Writer
    var outputFile *os.File

    for scanner.Scan() {
        if lineCount == 0 {
            outputPath := filepath.Join(outputDir, fmt.Sprintf("domains_part_%d.txt", fileIndex))
            outputFile, err = os.Create(outputPath)
            if err != nil {
                errorColor.Printf("Erreur lors de la création de %s : %v\n", outputPath, err)
                return
            }
            writer = bufio.NewWriter(outputFile)
            successColor.Printf("Création de %s\n", outputPath)
        }

        writer.WriteString(scanner.Text() + "\n")
        lineCount++

        if lineCount >= maxLines {
            writer.Flush()
            outputFile.Close()
            lineCount = 0
            fileIndex++
        }
    }

    if lineCount > 0 {
        writer.Flush()
        outputFile.Close()
    }

    if err := scanner.Err(); err != nil {
        errorColor.Printf("Erreur lors de la lecture de %s : %v\n", inputFile, err)
    }

    successColor.Printf("Division terminée : %d fichiers créés\n", fileIndex+1)
}

func deleteDomainsSplit(errorColor, successColor *color.Color) {
    outputDir := "./domains_split"
    if err := os.RemoveAll(outputDir); err != nil {
        errorColor.Printf("Erreur lors de la suppression de %s : %v\n", outputDir, err)
        return
    }
    successColor.Println("Répertoire domains_split supprimé avec succès")
}

func combineAWSKeys(errorColor, successColor *color.Color) {
    outputDir := "./keys"
    currentDate := time.Now().Format("2006-01-02")
    outputFile := fmt.Sprintf("%s-aws-keys-Backup.bak", currentDate)

    files, err := os.ReadDir(outputDir)
    if err != nil {
        errorColor.Printf("Erreur lors de la lecture du répertoire %s : %v\n", outputDir, err)
        return
    }

    out, err := os.Create(outputFile)
    if err != nil {
        errorColor.Printf("Erreur lors de la création de %s : %v\n", outputFile, err)
        return
    }
    defer out.Close()
    writer := bufio.NewWriter(out)

    for _, file := range files {
        if !file.IsDir() && (strings.Contains(file.Name(), "-aws-keys.txt") || strings.HasPrefix(file.Name(), currentDate)) {
            content, err := os.ReadFile(filepath.Join(outputDir, file.Name()))
            if err != nil {
                errorColor.Printf("Erreur lors de la lecture de %s : %v\n", file.Name(), err)
                continue
            }
            writer.WriteString(string(content) + "\n")
        }
    }

    writer.Flush()
    successColor.Printf("Clés AWS combinées dans %s\n", outputFile)
}

func combineRegularKeys(errorColor, successColor *color.Color) {
    outputDir := "./keys"
    currentDate := time.Now().Format("2006-01-02")
    outputFile := fmt.Sprintf("%s-keys-backup.bak", currentDate)

    files, err := os.ReadDir(outputDir)
    if err != nil {
        errorColor.Printf("Erreur lors de la lecture du répertoire %s : %v\n", outputDir, err)
        return
    }

    out, err := os.Create(outputFile)
    if err != nil {
        errorColor.Printf("Erreur lors de la création de %s : %v\n", outputFile, err)
        return
    }
    defer out.Close()
    writer := bufio.NewWriter(out)

    for _, file := range files {
        if !file.IsDir() && strings.Contains(file.Name(), "-keys.txt") && !strings.Contains(file.Name(), "-aws-keys.txt") {
            content, err := os.ReadFile(filepath.Join(outputDir, file.Name()))
            if err != nil {
                errorColor.Printf("Erreur lors de la lecture de %s : %v\n", file.Name(), err)
                continue
            }
            writer.WriteString(string(content) + "\n")
        }
    }

    writer.Flush()
    successColor.Printf("Clés régulières combinées dans %s\n", outputFile)
}

func deleteKeys(errorColor, successColor, promptColor *color.Color) {
    outputDir := "./keys"

    promptColor.Print("Voulez-vous vraiment supprimer tous les fichiers .txt dans le répertoire keys ? [O/n] : ")
    var response string
    fmt.Scanln(&response)
    response = strings.ToLower(response)
    if response != "" && response != "o" {
        successColor.Println("Opération annulée.")
        return
    }

    files, err := os.ReadDir(outputDir)
    if err != nil {
        errorColor.Printf("Erreur lors de la lecture du répertoire %s : %v\n", outputDir, err)
        return
    }

    deletedCount := 0
    for _, file := range files {
        if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
            outputPath := filepath.Join(outputDir, file.Name())
            if err := os.Remove(outputPath); err != nil {
                errorColor.Printf("Erreur lors de la suppression de %s : %v\n", file.Name(), err)
                continue
            }
            deletedCount++
        }
    }

    if deletedCount > 0 {
        successColor.Printf("%d fichiers .txt supprimés avec succès dans %s\n", deletedCount, outputDir)
    } else {
        successColor.Println("Aucun fichier .txt trouvé dans le répertoire keys.")
    }
}

func deleteDist(errorColor, successColor, promptColor *color.Color) {
    outputDir := "./dist"

    if _, err := os.Stat(outputDir); os.IsNotExist(err) {
        successColor.Println("Le répertoire dist n'existe pas.")
        return
    }

    promptColor.Print("Voulez-vous vraiment supprimer le répertoire dist ? [O/n] : ")
    var response string
    fmt.Scanln(&response)
    response = strings.ToLower(response)
    if response != "" && response != "o" {
        successColor.Println("Opération annulée.")
        return
    }

    if err := os.RemoveAll(outputDir); err != nil {
        errorColor.Printf("Erreur lors de la suppression de %s : %v\n", outputDir, err)
        return
    }
    successColor.Println("Répertoire dist supprimé avec succès")
}