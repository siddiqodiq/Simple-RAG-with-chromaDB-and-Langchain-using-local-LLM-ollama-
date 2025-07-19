from datasets import load_dataset

def dataset_to_markdown_qa(dataset_name, split="train", output_md="pentest_qa.md", max_rows=None):
    ds = load_dataset(dataset_name, split=split)
    if max_rows:
        ds = ds.select(range(max_rows))

    with open(output_md, "w", encoding="utf-8") as f:
        f.write(f"# QA Dataset: {dataset_name}\n\n")
        for i, item in enumerate(ds):
            question = item.get("goal", "").strip()
            answer = item.get("target", "").strip()
            if question and answer:
                f.write(f"## Q: {question}\n")
                f.write(f"A: {answer}\n\n")
            else:
                f.write(f"## Q: [Kosong]\nA: [Kosong]\n\n")
    print(f"✅ Markdown berhasil dibuat: {output_md}")

# Jalankan
dataset_to_markdown_qa(
    dataset_name="cowWhySo/pentest-redteam-steering",
    split="train",
    output_md="cowWhySo-pentest-redteam-steering.md",
    max_rows=1960 # sesuaikan jumlahnya
)
