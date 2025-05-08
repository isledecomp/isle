import hashlib
import json
import os
import sqlite3

from dotenv import load_dotenv
from openai import OpenAI

# Configuration
DATABASE_NAME = "code_embeddings.db"
# Define relevant file extensions (add more as needed)
SOURCE_FILE_EXTENSIONS = [
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".py",
    ".js",
    ".ts",
    ".java",
    ".go",
    ".rs",
    ".swift",
    ".kt",
    ".m",
    ".mm",
    ".cs",
    ".rb",
    ".php",
    ".pl",
    ".sh",
    ".lua",
    ".sql",
]  # Add header extensions too
ENV_FILE_PATH = ".env"
OPENAI_MODEL = "text-embedding-3-large"


def load_api_key(env_path: str) -> str:
    """Loads the OpenAI API key from the .env file."""
    load_dotenv(dotenv_path=env_path)
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError(
            "OPENAI_API_KEY not found in .env file or environment variables."
        )
    return api_key


def get_file_checksum(file_path: str) -> str:
    """Calculates the SHA256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return ""
    except IOError:
        print(f"Error: Could not read file at {file_path}")
        return ""


def get_openai_embedding(text: str, client: OpenAI) -> list[float] | None:
    """Gets the embedding for the given text using OpenAI API."""
    if not text.strip():  # Avoid sending empty strings to OpenAI
        print("Warning: Empty content, skipping embedding.")
        return None
    try:
        response = client.embeddings.create(input=text, model=OPENAI_MODEL)
        return response.data[0].embedding
    except Exception as e:
        print(f"Error getting embedding from OpenAI: {e}")
        return None


def find_files(start_path: str, extensions: list[str]) -> list[str]:
    """Recursively finds all files with given extensions in the start_path."""
    found_files = []
    for root, _, files in os.walk(start_path):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                found_files.append(os.path.join(root, file))
    return found_files


def init_db(db_name: str) -> sqlite3.Connection:
    """Initializes the SQLite database and creates the table if it doesn't exist."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    # Embedding dimension for text-embedding-3-large is 3072
    # Storing embeddings as TEXT (JSON string) or BLOB. TEXT is easier for inspection.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_embeddings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT UNIQUE NOT NULL,
        checksum TEXT NOT NULL,
        embedding TEXT NOT NULL, -- Store as JSON string
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_file_path ON file_embeddings (file_path);
    """)
    conn.commit()
    return conn


def process_file(file_path: str, client: OpenAI, conn: sqlite3.Connection):
    """Processes a single file: calculates checksum, gets embedding, and stores in DB."""
    print(f"Processing {file_path}...")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return

    current_checksum = get_file_checksum(file_path)
    if not current_checksum:  # Error occurred in checksum calculation
        return

    cursor = conn.cursor()
    cursor.execute(
        "SELECT checksum FROM file_embeddings WHERE file_path = ?", (file_path,)
    )
    result = cursor.fetchone()

    if result and result[0] == current_checksum:
        print(f"File {file_path} is unchanged. Skipping.")
        return

    embedding = get_openai_embedding(content, client)
    if not embedding:
        print(f"Could not get embedding for {file_path}. Skipping.")
        return

    embedding_json = json.dumps(embedding)  # Convert list to JSON string

    if result:  # File exists but checksum differs, so update
        print(f"File {file_path} has changed. Updating embedding.")
        cursor.execute(
            """
            UPDATE file_embeddings
            SET checksum = ?, embedding = ?, last_updated = CURRENT_TIMESTAMP
            WHERE file_path = ?
        """,
            (current_checksum, embedding_json, file_path),
        )
    else:  # New file, insert
        print(f"New file {file_path}. Adding embedding.")
        cursor.execute(
            """
            INSERT INTO file_embeddings (file_path, checksum, embedding)
            VALUES (?, ?, ?)
        """,
            (file_path, current_checksum, embedding_json),
        )
    conn.commit()
    print(f"Successfully processed and stored embedding for {file_path}.")


def main():
    """Main function to orchestrate the embedding process."""
    # 0. Create .env if it doesn't exist
    if not os.path.exists(ENV_FILE_PATH):
        with open(ENV_FILE_PATH, "w") as f:
            f.write("OPENAI_API_KEY='YOUR_API_KEY_HERE'\\n")
        print(f"Created {ENV_FILE_PATH}. Please add your OpenAI API key to it.")
        return

    # 1. Load API Key
    try:
        api_key = load_api_key(ENV_FILE_PATH)
    except ValueError as e:
        print(e)
        return

    # 2. Initialize OpenAI client
    try:
        client = OpenAI(api_key=api_key)
    except Exception as e:
        print(f"Failed to initialize OpenAI client: {e}")
        return

    # 3. Initialize DB
    conn = init_db(DATABASE_NAME)

    # 4. Get target directory
    target_directory = input("Enter the root directory of your codebase to scan: ")
    if not os.path.isdir(target_directory):
        print(f"Error: Directory '{target_directory}' not found.")
        conn.close()
        return

    print(
        f"Scanning for files in {target_directory} with extensions: {', '.join(SOURCE_FILE_EXTENSIONS)}"
    )

    # 5. Find files
    files_to_process = find_files(target_directory, SOURCE_FILE_EXTENSIONS)
    if not files_to_process:
        print("No relevant files found to process.")
        conn.close()
        return

    print(f"Found {len(files_to_process)} files to process.")

    # 6. Process each file
    for n, file_path in enumerate(files_to_process):
        print(f"--- Processing file {n+1}/{len(files_to_process)} ---")
        process_file(file_path, client, conn)

    conn.close()
    print("\nEmbedding process completed.")


if __name__ == "__main__":
    main()
