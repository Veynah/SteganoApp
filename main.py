from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
from PIL import Image
import base64
import os
import io
import tempfile

app = Flask(__name__)

AES_ALGORITHM = "AES"
HASH_ALGORITHM = "SHA-256"
END_DELIMITER = "1111111111111110"
KEY_DELIMITER = "0000000000000001"
IV_LENGTH = 16
"""
# Documentation du Code Python : Application de Stéganographie avec Chiffrement

## 1. Introduction
Ce script Python implémente une application de stéganographie qui permet de cacher un message chiffré à l'intérieur d'une image. L'application utilise le chiffrement AES pour sécuriser le message avant de l'encoder dans les bits les moins significatifs (LSB) des pixels de l'image. Le processus est réversible, permettant de décoder le message à partir de l'image tout en conservant la structure originale du message.

## 2. Bibliothèques Utilisées
- **Flask** : Utilisé pour créer l'interface web permettant de télécharger des images, d'encoder des messages et de décoder des messages cachés.
- **Werkzeug** : Fournit des utilitaires pour sécuriser les noms de fichiers téléchargés.
- **PyCryptodome** : Implémente les algorithmes de chiffrement AES, et est utilisé ici pour chiffrer et déchiffrer les messages.
- **PIL (Pillow)** : Bibliothèque pour le traitement des images, utilisée pour lire, manipuler et sauvegarder des images.
- **Base64** : Utilisé pour encoder le message chiffré en chaîne de caractères, facilitant son encodage dans l'image.
- **Tempfile** : Permet de gérer les fichiers temporaires de manière portable, compatible avec Windows, Linux et macOS.

## 3. Fonctionnalités Clés et Raison d'Être
### a. Chiffrement AES en mode CBC
- **Pourquoi** : Le chiffrement AES (Advanced Encryption Standard) est un algorithme de chiffrement symétrique largement utilisé pour sécuriser les données. Le mode CBC (Cipher Block Chaining) est choisi car il offre une meilleure sécurité que le mode ECB en rendant chaque bloc chiffré dépendant du bloc précédent, ce qui masque les motifs répétitifs dans le texte en clair.
- **Comment** : Un vecteur d'initialisation (IV) est généré de manière aléatoire pour chaque chiffrement. L'IV est préfixé au message chiffré, permettant au destinataire de le récupérer pour le déchiffrement.

### b. Encodage dans les Bits les Moins Significatifs (LSB)
- **Pourquoi** : Les bits les moins significatifs des pixels d'une image sont modifiés pour cacher le message chiffré. Cette méthode est utilisée car elle altère très peu l'apparence visuelle de l'image, rendant la présence du message difficile à détecter.
- **Comment** : Chaque bit du message binaire chiffré est inséré dans le LSB des composantes de couleur des pixels (rouge, vert, bleu). Si l'image contient un canal alpha (transparence), ce dernier est préservé pour ne pas altérer les propriétés visuelles de l'image.

### c. Gestion des Fichiers Temporaires
- **Pourquoi** : Pour garantir que le code fonctionne sur différents systèmes d'exploitation (Windows, Linux, macOS), la gestion des fichiers temporaires est faite via le module `tempfile`. Cela permet d'éviter les erreurs liées à des chemins de fichiers spécifiques à certains systèmes.
- **Comment** : Les images téléchargées sont enregistrées dans des fichiers temporaires, puis supprimées après utilisation pour garantir que le système ne conserve pas de fichiers inutiles.

## 4. Processus d'Encodage
1. L'utilisateur télécharge une image et saisit un message à encoder.
2. Le message est chiffré en utilisant AES en mode CBC avec un IV aléatoire.
3. Le message chiffré est converti en une chaîne binaire.
4. Les bits du message binaire sont insérés dans les LSB des pixels de l'image.
5. L'image modifiée est sauvegardée et envoyée à l'utilisateur.

## 5. Processus de Décodage
1. L'utilisateur télécharge une image contenant un message caché et saisit la clé secrète.
2. Les bits sont extraits des LSB des pixels de l'image.
3. Le message binaire est reconstruit et converti en une chaîne de caractères.
4. Le message chiffré est déchiffré en utilisant l'IV extrait et la clé secrète.
5. Le message original est restitué à l'utilisateur.

## 6. Conclusion
Ce script permet de cacher des informations de manière sécurisée dans une image tout en maintenant une compatibilité avec les différents systèmes d'exploitation. Le processus d'encodage/décodage garantit que le message peut être récupéré sans altération, à condition que l'image ne soit pas modifiée après l'encodage. Le chiffrement AES en mode CBC assure une sécurité renforcée, rendant difficile la récupération du message sans la clé appropriée.

"""


def generate_key(secret_key):
    key_bytes = sha256(secret_key.encode()).digest()
    return key_bytes[:16]


def encrypt(message, secret_key):
    key = generate_key(secret_key)
    iv = os.urandom(IV_LENGTH)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_bytes = iv + cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_bytes).decode()


def decrypt(encrypted_message, secret_key):
    key = generate_key(secret_key)
    encrypted_bytes = base64.b64decode(encrypted_message)
    iv = encrypted_bytes[:IV_LENGTH]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes[IV_LENGTH:]), AES.block_size)
    return decrypted_bytes.decode()


def encode_message(image_path, message, secret_key):
    encrypted_message = encrypt(message, secret_key)
    combined_message = encrypted_message + KEY_DELIMITER
    binary_message = "".join([format(ord(c), "08b") for c in combined_message])
    binary_message += END_DELIMITER

    image = Image.open(image_path)
    pixels = list(image.getdata())
    encoded_pixels = []

    message_index = 0
    for pixel in pixels:
        r, g, b, *a = pixel
        if message_index < len(binary_message):
            r = (r & 0xFE) | int(binary_message[message_index])
            message_index += 1
        if message_index < len(binary_message):
            g = (g & 0xFE) | int(binary_message[message_index])
            message_index += 1
        if message_index < len(binary_message):
            b = (b & 0xFE) | int(binary_message[message_index])
            message_index += 1
        if a:
            encoded_pixels.append((r, g, b, *a))
        else:
            encoded_pixels.append((r, g, b))
    encoded_image = Image.new(image.mode, image.size)
    encoded_image.putdata(encoded_pixels)

    temp_file = io.BytesIO()
    encoded_image.save(temp_file, format="PNG")
    temp_file.seek(0)
    return temp_file


def decode_message(image_path, secret_key):
    image = Image.open(image_path)
    pixels = list(image.getdata())
    binary_message = ""
    for pixel in pixels:
        r, g, b, *a = pixel
        binary_message += str(r & 1)
        binary_message += str(g & 1)
        binary_message += str(b & 1)

    end_index = binary_message.find(END_DELIMITER)

    if end_index == -1:
        raise ValueError("No hidden message found in the image.")

    combined_message = "".join(
        [chr(int(binary_message[i : i + 8], 2)) for i in range(0, end_index, 8)]
    )
    key_delimiter_index = combined_message.find(KEY_DELIMITER)

    if key_delimiter_index == -1:
        raise ValueError("No encoded secret key found in the image.")

    encrypted_message = combined_message[:key_delimiter_index]
    return decrypt(encrypted_message, secret_key)


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html", message="")


@app.route("/encode", methods=["POST"])
def encode():
    image = request.files["inputImage"]
    message = request.form["message"]
    secret_key = request.form["secretKey"]

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as temp:
        image_path = temp.name
        image.save(image_path)

    try:
        encoded_image = encode_message(image_path, message, secret_key)
        return send_file(
            encoded_image,
            mimetype="image/png",
            as_attachment=True,
            download_name="encoded_image.png",
        )
    except Exception as e:
        return render_template("index.html", message=str(e))
    finally:
        if os.path.exists(image_path):
            os.remove(image_path)


@app.route("/decode", methods=["POST"])
def decode():
    image = request.files["encodedImage"]
    secret_key = request.form["secretKey"]

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as temp:
        image_path = temp.name
        image.save(image_path)

    try:
        message = decode_message(image_path, secret_key)
        return render_template("index.html", message=message)
    except Exception as e:
        return render_template("index.html", message=str(e))
    finally:
        if os.path.exists(image_path):
            os.remove(image_path)


if __name__ == "__main__":
    app.run(debug=True, port=8000)
