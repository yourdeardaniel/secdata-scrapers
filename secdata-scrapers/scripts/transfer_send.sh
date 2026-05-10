#!/bin/bash
# ============================================================
# transfer_send.sh — Run on the SENDING VPS
# ============================================================
# Compresses and serves your data files over HTTP so the
# receiving VPS can download them with a single wget command.
#
# Usage:
#   bash scripts/transfer_send.sh          # serves everything needed
#   bash scripts/transfer_send.sh raw      # only serve raw_docs.jsonl (4090→H100)
#   bash scripts/transfer_send.sh filtered # only serve filtered.jsonl (H100→4090)
#   bash scripts/transfer_send.sh final    # only serve final_dataset.jsonl (→RunPod)

set -e

MODE=${1:-"all"}
PORT=8888
SERVE_DIR="/tmp/transfer_serve"
mkdir -p "$SERVE_DIR"

echo ""
echo "=== Transfer Sender ==="

# ── Compress files based on mode ──────────────────────────────

compress_file() {
    local src="$1"
    local name="$2"
    if [ ! -f "$src" ]; then
        echo "  SKIP: $src not found"
        return
    fi
    local size=$(du -sh "$src" | cut -f1)
    echo "  Compressing $name ($size)..."
    gzip -c "$src" > "$SERVE_DIR/${name}.gz"
    local compressed=$(du -sh "$SERVE_DIR/${name}.gz" | cut -f1)
    echo "  Compressed: $size → $compressed"

    # generate checksum for verification on the receiving end
    md5sum "$SERVE_DIR/${name}.gz" | awk '{print $1}' > "$SERVE_DIR/${name}.gz.md5"
    echo "  Checksum: $(cat $SERVE_DIR/${name}.gz.md5)"
}

case "$MODE" in
    raw|"4090-to-h100")
        echo "Mode: 4090 → H100 (raw docs + checkpoint)"
        compress_file "data/raw/raw_docs.jsonl"       "raw_docs.jsonl"
        compress_file "data/checkpoint.json"          "checkpoint.json"
        ;;
    filtered|"h100-to-4090")
        echo "Mode: H100 → 4090 (filtered + checkpoint)"
        compress_file "data/processed/filtered.jsonl" "filtered.jsonl"
        compress_file "data/checkpoint.json"          "checkpoint.json"
        ;;
    final|"to-runpod")
        echo "Mode: 4090 → RunPod A100 (final dataset)"
        compress_file "data/final_dataset.jsonl"      "final_dataset.jsonl"
        ;;
    all)
        echo "Mode: all files"
        compress_file "data/raw/raw_docs.jsonl"       "raw_docs.jsonl"
        compress_file "data/processed/filtered.jsonl" "filtered.jsonl"
        compress_file "data/final_dataset.jsonl"      "final_dataset.jsonl"
        compress_file "data/checkpoint.json"          "checkpoint.json"
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Usage: bash transfer_send.sh [raw|filtered|final|all]"
        exit 1
        ;;
esac

# ── Get this machine's public IP ─────────────────────────────
MY_IP=$(curl -s https://api.ipify.org 2>/dev/null || \
        curl -s https://ipecho.net/plain 2>/dev/null || \
        hostname -I | awk '{print $1}')

echo ""
echo "=== Files ready to serve ==="
ls -lh "$SERVE_DIR"

echo ""
echo "=== Starting HTTP server on port $PORT ==="
echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  On the RECEIVING VPS, run:                         │"
echo "  │                                                     │"
echo "  │  bash scripts/transfer_receive.sh $MY_IP $PORT $MODE"
echo "  │                                                     │"
echo "  │  Or manually:                                       │"
echo "  │  wget http://$MY_IP:$PORT/raw_docs.jsonl.gz         │"
echo "  └─────────────────────────────────────────────────────┘"
echo ""
echo "Press Ctrl+C to stop the server when transfer is complete."
echo ""

# serve files — Python's built-in HTTP server, no dependencies needed
cd "$SERVE_DIR"
python3 -m http.server $PORT
