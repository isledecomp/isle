import { config } from "dotenv";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { OpenAI } from "openai";
import { createClient } from "@libsql/client";
import {
	encode,
	encodeChat,
	decode,
	isWithinTokenLimit,
	encodeGenerator,
	decodeGenerator,
	decodeAsyncGenerator,
} from "gpt-tokenizer";

// configuration
const DB_PATH = "file:code_embeddings.db";
const SOURCE_FILE_EXTENSIONS = [".c", ".cpp", ".h", ".hpp", ".hxx"];
const OPENAI_MODEL = "text-embedding-3-large";
const EMBEDDING_DIMENSION = 3072;

// env
config();
const EnvSchema = z.object({ OPENAI_API_KEY: z.string() });
const { OPENAI_API_KEY } = EnvSchema.parse(process.env);

// clients
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });
const db = createClient({ url: DB_PATH });

await db.execute(
	`CREATE TABLE IF NOT EXISTS file_embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT UNIQUE NOT NULL,
    checksum TEXT NOT NULL,
    embedding F32_BLOB(${EMBEDDING_DIMENSION}) NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
	CREATE INDEX IF NOT EXISTS file_embeddings_idx ON file_embeddings (libsql_vector_idx(embedding));`,
);

const getChecksum = (filePath: string): string => {
	const hash = createHash("sha256");
	hash.update(readFileSync(filePath));
	return hash.digest("hex");
};

const getEmbedding = async (content: string): Promise<number[]> => {
	const token_limit = 8000;
	let c = content;
	while (!isWithinTokenLimit(c, token_limit)) {
		c = c.slice(0, c.length - 100);
	}
	const { data } = await openai.embeddings.create({
		model: OPENAI_MODEL,
		input: c,
		encoding_format: "float",
	});
	return data[0].embedding as unknown as number[];
};

const findFiles = (startDir: string): string[] => {
	const stack = [startDir];
	const files: string[] = [];
	while (stack.length) {
		const current = stack.pop() as string;
		for (const entry of readdirSync(current)) {
			const fullPath = path.join(current, entry);
			const stats = statSync(fullPath);
			if (stats.isDirectory()) {
				stack.push(fullPath);
			} else if (SOURCE_FILE_EXTENSIONS.some((ext) => entry.endsWith(ext))) {
				files.push(fullPath);
			}
		}
	}
	return files;
};

const processFile = async (filePath: string) => {
	const content = readFileSync(filePath, "utf8");
	if (!content.trim()) {
		console.log(`Skipping ${filePath} because it is empty`);
		return;
	}

	const checksum = getChecksum(filePath);
	const existing = await db.execute(
		"SELECT checksum FROM file_embeddings WHERE file_path = ?",
		[filePath],
	);
	const row = existing.rows[0];
	if (row && row.checksum === checksum) {
		console.log(`Skipping ${filePath} because it already exists`);
		return;
	}

	const embedding = await getEmbedding(content);

	// await db.execute(
	// 	`INSERT INTO file_embeddings (file_path, checksum, embedding) VALUES ('${filePath}', '${checksum}', vector32('[${embedding.join(",")}]'))`,
	// );
	await db.execute(
		"INSERT INTO file_embeddings (file_path, checksum, embedding) VALUES (?, ?, ?)",
		[filePath, checksum, new Uint8Array(embedding)],
	);
};

const targetDirectory = process.argv[2] ?? ".";
if (!statSync(targetDirectory).isDirectory()) {
	console.error(`Directory '${targetDirectory}' not found`);
	process.exit(1);
}
const files = findFiles(targetDirectory);
for (let n = 0; n < files.length; ++n) {
	console.log(`Processing ${files[n]} (${n + 1}/${files.length})`);
	await processFile(files[n]);
}
console.log("Done");
process.exit(0);
