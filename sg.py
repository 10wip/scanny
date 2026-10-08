# -*- coding: utf-8 -*-
import re

# Demande à l'utilisateur le nom du fichier à traiter
input_file = input("Entrez le nom du fichier .txt à analyser : ")
output_file = 'sg.txt'

# Définition du motif pour les clés API SendGrid
pattern = r'SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}'

# Liste pour stocker les clés trouvées
found_keys = []

try:
    # Essayer d'ouvrir le fichier avec un encodage différent si 'utf-8' échoue
    with open(input_file, 'r', encoding='utf-8') as file:
        content = file.read()
        found_keys = re.findall(pattern, content)

    # Écriture des clés trouvées dans le fichier sg.txt
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for key in found_keys:
            outfile.write(key + '\n')

    print(f"Clés API SendGrid trouvées et enregistrées dans {output_file}.")

except UnicodeDecodeError:
    # Si l'encodage 'utf-8' échoue, essayons un encodage alternatif (par exemple, 'ISO-8859-1')
    try:
        with open(input_file, 'r', encoding='ISO-8859-1') as file:
            content = file.read()
            found_keys = re.findall(pattern, content)

        # Écriture des clés trouvées dans le fichier sg.txt
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for key in found_keys:
                outfile.write(key + '\n')

        print(f"Clés API SendGrid trouvées et enregistrées dans {output_file}.")
    except FileNotFoundError:
        print(f"Le fichier {input_file} n'a pas été trouvé.")
    except Exception as e:
        print(f"Une erreur est survenue : {e}")

except FileNotFoundError:
    print(f"Le fichier {input_file} n'a pas été trouvé.")
except Exception as e:
    print(f"Une erreur est survenue : {e}")
