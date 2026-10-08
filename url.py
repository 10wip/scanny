import requests
from requests.auth import HTTPBasicAuth

def extract_lines():
    # Demander l'URL à l'utilisateur
    index_url = input("Entrez l'URL de l'index (ex: https://tldonly.domainsproject.org/antigua_and_barbuda/domain2multi-ag00.txt): ")

    # Authentification de base
    username = "dada"
    password = "veeVeem0"

    # Faire la requête HTTP avec l'authentification
    response = requests.get(index_url, auth=HTTPBasicAuth(username, password))

    if response.status_code == 200:
        print("Connexion réussie et récupération du fichier...")
        
        # Extraire le contenu brut de la réponse
        lines = response.text.splitlines()

        # Ouvrir le fichier en mode append ('a') pour ajouter au lieu de remplacer
        with open("urlrez.txt", "a") as file:
            for line in lines:
                file.write(line + "\n")
        
        print(f"Les lignes ont été extraites et ajoutées dans 'urlrez.txt'.")
    else:
        print(f"Erreur de connexion: {response.status_code}")

if __name__ == "__main__":
    extract_lines()
