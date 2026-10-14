"""
AI-Based Malicious URL Detection System
Dataset Preparation & Quality Pipeline
Author: Hackathon Engineering Pipeline

OBJECTIVE:
Loads a raw labeled URL dataset (CSV), inspects data quality, deduplicates records,
maps multi-class labels into standard binary classes ('LEGITIMATE' and 'MALICIOUS'),
and performs stratified splitting into Train, Validation, and Test sets without data leakage.
"""

import os
import sys
import csv
import json
import random
from collections import Counter
from typing import Dict, List, Tuple, Any, Optional

# ==============================================================================
# 1. CONFIGURATION SECTION (Customize these for your specific dataset)
# ==============================================================================

# Common column name aliases if not explicitly specified
DEFAULT_URL_COLUMNS = ['url', 'URL', 'url_link', 'domain', 'link', 'website']
DEFAULT_LABEL_COLUMNS = ['type', 'label', 'class', 'result', 'status', 'category', 'target']

# Configurable Label Mapping:
# Maps various raw dataset labels into our two standard target classes:
# - 'LEGITIMATE'
# - 'MALICIOUS'
LABEL_MAPPING: Dict[str, str] = {
    # Benign / Safe Variants
    'benign': 'LEGITIMATE',
    'legitimate': 'LEGITIMATE',
    'good': 'LEGITIMATE',
    'safe': 'LEGITIMATE',
    'clean': 'LEGITIMATE',
    'ham': 'LEGITIMATE',
    '0': 'LEGITIMATE',
    '0.0': 'LEGITIMATE',

    # Malicious / Attack Variants
    'malicious': 'MALICIOUS',
    'phishing': 'MALICIOUS',
    'malware': 'MALICIOUS',
    'defacement': 'MALICIOUS',
    'bad': 'MALICIOUS',
    'spam': 'MALICIOUS',
    'fraud': 'MALICIOUS',
    'trojan': 'MALICIOUS',
    '1': 'MALICIOUS',
    '1.0': 'MALICIOUS',
    '2': 'MALICIOUS',
    '2.0': 'MALICIOUS'
}

# Split Ratios (must sum to 1.0)
TRAIN_RATIO = 0.70       # 70% for model training
VAL_RATIO = 0.15         # 15% for hyperparameter tuning & early stopping
TEST_RATIO = 0.15        # 15% holdout test set for final unbiased evaluation
RANDOM_SEED = 42         # Ensures reproducible splits across runs


# ==============================================================================
# 2. CORE DATASET PIPELINE CLASS
# ==============================================================================

class UrlDatasetPipeline:
    def __init__(
        self,
        raw_csv_path: str,
        output_dir: str = 'data/processed',
        url_col: Optional[str] = None,
        label_col: Optional[str] = None,
        label_map: Optional[Dict[str, str]] = None,
        seed: int = RANDOM_SEED
    ):
        self.raw_csv_path = raw_csv_path
        self.output_dir = output_dir
        self.url_col = url_col
        self.label_col = label_col
        self.label_map = label_map or LABEL_MAPPING
        self.seed = seed

        self.stats: Dict[str, Any] = {
            "total_raw_rows": 0,
            "missing_url_count": 0,
            "missing_label_count": 0,
            "duplicate_urls_removed": 0,
            "conflicting_label_urls_removed": 0,
            "unmapped_labels_dropped": 0,
            "unmapped_label_values": [],
            "clean_sample_count": 0,
            "class_distribution": {},
            "split_counts": {}
        }

    def _auto_detect_columns(self, fieldnames: List[str]) -> Tuple[str, str]:
        """Automatically detects URL and Label column names if not provided."""
        detected_url = self.url_col
        detected_label = self.label_col

        lower_fields = {f.lower().strip(): f for f in fieldnames}

        # Detect URL column
        if not detected_url:
            for candidate in DEFAULT_URL_COLUMNS:
                if candidate.lower() in lower_fields:
                    detected_url = lower_fields[candidate.lower()]
                    break

        # Detect Label column
        if not detected_label:
            for candidate in DEFAULT_LABEL_COLUMNS:
                if candidate.lower() in lower_fields:
                    detected_label = lower_fields[candidate.lower()]
                    break

        if not detected_url or not detected_label:
            raise ValueError(
                f"Could not identify URL or Label columns automatically in CSV header: {fieldnames}. "
                f"Please specify url_col and label_col explicitly."
            )

        print(f"✓ Detected columns -> URL Column: '{detected_url}', Label Column: '{detected_label}'")
        return detected_url, detected_label

    def load_and_inspect(self) -> List[Tuple[str, str]]:
        """
        Loads CSV, inspects data quality, deduplicates URLs, resolves conflicting
        labels, and normalizes classes into LEGITIMATE and MALICIOUS.
        """
        if not os.path.exists(self.raw_csv_path):
            raise FileNotFoundError(f"Dataset file not found at: {self.raw_csv_path}")

        print("\n" + "=" * 70)
        print("STAGE 1: INSPECTING DATASET & CLEANING")
        print("=" * 70)

        # Temporary storage for tracking duplicates and conflicting labels
        url_to_raw_labels: Dict[str, List[str]] = {}

        with open(self.raw_csv_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV file appears to be empty or missing headers.")

            url_col, label_col = self._auto_detect_columns(reader.fieldnames)

            for row in reader:
                self.stats["total_raw_rows"] += 1
                raw_url = (row.get(url_col) or '').strip()
                raw_label = (row.get(label_col) or '').strip()

                # Check for missing values
                if not raw_url:
                    self.stats["missing_url_count"] += 1
                    continue
                if not raw_label:
                    self.stats["missing_label_count"] += 1
                    continue

                if raw_url not in url_to_raw_labels:
                    url_to_raw_labels[raw_url] = []
                url_to_raw_labels[raw_url].append(raw_label)

        print(f"Total raw records loaded: {self.stats['total_raw_rows']}")
        print(f"Missing URL records dropped: {self.stats['missing_url_count']}")
        print(f"Missing Label records dropped: {self.stats['missing_label_count']}")

        # Deduplication and Label Normalization
        clean_records: List[Tuple[str, str]] = []
        unmapped_set = set()

        for url, raw_labels in url_to_raw_labels.items():
            # If multiple records existed for this URL, log duplicate count
            if len(raw_labels) > 1:
                self.stats["duplicate_urls_removed"] += (len(raw_labels) - 1)

            # Map raw labels
            normalized_labels = []
            for lbl in raw_labels:
                key = lbl.lower()
                if key in self.label_map:
                    normalized_labels.append(self.label_map[key])
                else:
                    unmapped_set.add(lbl)

            # If all labels for this URL were unmapped, skip
            if not normalized_labels:
                self.stats["unmapped_labels_dropped"] += len(raw_labels)
                continue

            # Check for label conflict (e.g. marked as both LEGITIMATE and MALICIOUS)
            unique_mapped = set(normalized_labels)
            if len(unique_mapped) > 1:
                # Conflicting classification: unsafe to use as ground truth
                self.stats["conflicting_label_urls_removed"] += 1
                continue

            # Clean, non-conflicting normalized sample
            final_label = list(unique_mapped)[0]
            clean_records.append((url, final_label))

        self.stats["unmapped_label_values"] = sorted(list(unmapped_set))
        self.stats["clean_sample_count"] = len(clean_records)

        # Compute Class Balance
        class_counts = Counter(label for _, label in clean_records)
        self.stats["class_distribution"] = dict(class_counts)

        print("\nData Quality Summary:")
        print(f" - Duplicate URLs purged: {self.stats['duplicate_urls_removed']}")
        print(f" - Conflicting label URLs purged: {self.stats['conflicting_label_urls_removed']}")
        if unmapped_set:
            print(f" - Unmapped label values dropped: {self.stats['unmapped_label_values']}")
        print(f" - Total clean, unique URLs ready: {self.stats['clean_sample_count']}")

        total_clean = len(clean_records)
        if total_clean > 0:
            print("\nClass Distribution:")
            for cls_name, count in class_counts.items():
                pct = (count / total_clean) * 100
                print(f"   [{cls_name}]: {count} samples ({pct:.1f}%)")

            # Check imbalance ratio
            if len(class_counts) == 2:
                legit_c = class_counts.get('LEGITIMATE', 0)
                mal_c = class_counts.get('MALICIOUS', 0)
                if legit_c > 0 and mal_c > 0:
                    ratio = max(legit_c, mal_c) / min(legit_c, mal_c)
                    print(f"   Imbalance Ratio: {ratio:.2f}:1")
                    if ratio > 3.0:
                        print("   ⚠ Note: Moderate to severe class imbalance detected. Stratification is crucial.")

        return clean_records

    def stratified_split(
        self, records: List[Tuple[str, str]]
    ) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], List[Tuple[str, str]]]:
        """
        Splits dataset into Train (70%), Validation (15%), and Test (15%)
        using stratified sampling to preserve the exact class ratio across all splits.
        """
        print("\n" + "=" * 70)
        print("STAGE 2: STRATIFIED SPLITTING (NO DATA LEAKAGE)")
        print("=" * 70)

        # Group samples by class
        by_class: Dict[str, List[Tuple[str, str]]] = {}
        for item in records:
            cls = item[1]
            if cls not in by_class:
                by_class[cls] = []
            by_class[cls].append(item)

        train_set: List[Tuple[str, str]] = []
        val_set: List[Tuple[str, str]] = []
        test_set: List[Tuple[str, str]] = []

        rng = random.Random(self.seed)

        for cls, items in by_class.items():
            # Deterministic shuffle within class
            shuffled = list(items)
            rng.shuffle(shuffled)

            total = len(shuffled)
            train_end = int(total * TRAIN_RATIO)
            val_end = train_end + int(total * VAL_RATIO)

            cls_train = shuffled[:train_end]
            cls_val = shuffled[train_end:val_end]
            cls_test = shuffled[val_end:]

            train_set.extend(cls_train)
            val_set.extend(cls_val)
            test_set.extend(cls_test)

        # Final shuffle of each split
        rng.shuffle(train_set)
        rng.shuffle(val_set)
        rng.shuffle(test_set)

        # Verify zero overlap / data leakage between splits
        train_urls = set(u for u, _ in train_set)
        val_urls = set(u for u, _ in val_set)
        test_urls = set(u for u, _ in test_set)

        overlap_tv = train_urls.intersection(val_urls)
        overlap_tt = train_urls.intersection(test_urls)
        overlap_vt = val_urls.intersection(test_urls)

        if overlap_tv or overlap_tt or overlap_vt:
            raise AssertionError("CRITICAL ERROR: Data leakage detected! Overlapping URLs exist between splits.")

        print("✓ Verified zero overlap: No URL appears in more than one split.")

        # Record split statistics
        def count_classes(dataset):
            c = Counter(label for _, label in dataset)
            return {"total": len(dataset), "LEGITIMATE": c.get('LEGITIMATE', 0), "MALICIOUS": c.get('MALICIOUS', 0)}

        self.stats["split_counts"] = {
            "train": count_classes(train_set),
            "val": count_classes(val_set),
            "test": count_classes(test_set)
        }

        print("\nSplit Distribution Report:")
        for split_name, counts in self.stats["split_counts"].items():
            print(
                f" - {split_name.upper():<6}: {counts['total']:>5} URLs | "
                f"Legitimate: {counts['LEGITIMATE']:>4} | "
                f"Malicious: {counts['MALICIOUS']:>4}"
            )

        return train_set, val_set, test_set

    def save_outputs(
        self,
        clean_records: List[Tuple[str, str]],
        train_set: List[Tuple[str, str]],
        val_set: List[Tuple[str, str]],
        test_set: List[Tuple[str, str]]
    ):
        """Saves clean dataset, individual split CSVs, and a summary report."""
        print("\n" + "=" * 70)
        print("STAGE 3: SAVING PROCESSED DATASETS")
        print("=" * 70)

        os.makedirs(self.output_dir, exist_ok=True)

        def write_csv(filename: str, rows: List[Tuple[str, str]]):
            path = os.path.join(self.output_dir, filename)
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['url', 'label'])
                writer.writerows(rows)
            print(f"✓ Saved {len(rows):>5} samples to -> {path}")

        write_csv('clean_dataset.csv', clean_records)
        write_csv('train.csv', train_set)
        write_csv('val.csv', val_set)
        write_csv('test.csv', test_set)

        # Write summary report JSON
        report_path = os.path.join(self.output_dir, 'summary_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=2)
        print(f"✓ Saved dataset statistics report -> {report_path}")

    def run(self):
        """Executes full preparation pipeline."""
        clean_records = self.load_and_inspect()
        if not clean_records:
            print("\n❌ Error: No clean records remaining after validation.")
            return

        train_set, val_set, test_set = self.stratified_split(clean_records)
        self.save_outputs(clean_records, train_set, val_set, test_set)
        print("\n🎉 Dataset preparation complete! Ready for model training.")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="AI-Based Malicious URL Detection - Dataset Pipeline")
    parser.add_argument("pos_input", nargs="?", default=None, help="Path to raw CSV (positional)")
    parser.add_argument("pos_output", nargs="?", default=None, help="Output directory (positional)")
    parser.add_argument("--input", "-i", dest="flag_input", default=None, help="Path to raw CSV file")
    parser.add_argument("--output", "-o", dest="flag_output", default=None, help="Output directory")
    parser.add_argument("--url-col", default=None, help="Explicit URL column name")
    parser.add_argument("--label-col", default=None, help="Explicit Label column name")

    args = parser.parse_args()

    # Determine input path
    raw_path = args.flag_input or args.pos_input
    if not raw_path:
        raw_path = 'data/raw/dataset.csv' if os.path.exists('data/raw/dataset.csv') else 'data/raw/hackathon_training_corpus.csv'

    output_directory = args.flag_output or args.pos_output or 'data/processed'

    print("=" * 70)
    print("AI-BASED MALICIOUS URL DETECTION SYSTEM - DATASET PIPELINE")
    print(f"Target raw dataset: {raw_path}")
    print(f"Output directory:   {output_directory}")
    print("=" * 70)

    pipeline = UrlDatasetPipeline(
        raw_csv_path=raw_path,
        output_dir=output_directory,
        url_col=args.url_col,
        label_col=args.label_col
    )
    pipeline.run()

