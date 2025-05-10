import { config } from "dotenv";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { OpenAI } from "openai";
import { isWithinTokenLimit } from "gpt-tokenizer";

// configuration
const SOURCE_FILE_EXTENSIONS = [".c", ".cpp", ".h", ".hpp", ".hxx"];
const OPENAI_MODEL = "text-embedding-3-large";

// env
config();
const EnvSchema = z.object({ OPENAI_API_KEY: z.string() });
const { OPENAI_API_KEY } = EnvSchema.parse(process.env);

// clients
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

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
	return data[0].embedding;
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

const processFile = async (
	filePath: string,
	embeddings: Record<string, number[]>,
) => {
	const content = readFileSync(filePath, "utf8");
	if (!content.trim()) {
		console.log(`Skipping ${filePath} because it is empty`);
		return;
	}

	if (embeddings[filePath] != null) {
		console.log(`Skipping ${filePath} because it already exists`);
		return;
	}

	const embedding = await getEmbedding(content);

	embeddings[filePath] = embedding;
};

const targetDirectory = process.argv[2] ?? ".";
if (!statSync(targetDirectory).isDirectory()) {
	console.error(`Directory '${targetDirectory}' not found`);
	process.exit(1);
}
const files = findFiles(targetDirectory);
const embeddings: Record<string, number[]> = {};
for (let n = 0; n < files.length; ++n) {
	console.log(`Processing ${files[n]} (${n + 1}/${files.length})`);
	await processFile(files[n], embeddings);
}

writeFileSync("file_embeddings.json", JSON.stringify(embeddings, null, 2));
console.log("Done");
process.exit(0);
