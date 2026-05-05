package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf/execve.c -- -I../headers

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfEvent struct {
	Pid  uint32
	Comm [16]byte
}

// -------------------------------------------------------------------
// PHASE 2: In-Memory "Blackbox" Circular Buffer
// -------------------------------------------------------------------
type ForensicEvent struct {
	Timestamp string `json:"timestamp"`
	PID       uint32 `json:"pid"`
	Command   string `json:"command"`
}

const maxBufferSize = 10000 // Hold last 10,000 syscalls

type BlackboxBuffer struct {
	events []ForensicEvent
	head   int
	count  int
}

func NewBlackboxBuffer() *BlackboxBuffer {
	return &BlackboxBuffer{
		events: make([]ForensicEvent, maxBufferSize),
	}
}

func (b *BlackboxBuffer) Add(event ForensicEvent) {
	b.events[b.head] = event
	b.head = (b.head + 1) % maxBufferSize
	if b.count < maxBufferSize {
		b.count++
	}
}

// This is triggered by K8s Pre-Stop hook
func (b *BlackboxBuffer) DumpAndHash() {
	log.Println("\n⚠️ [CRITICAL] Term signal received! Freezing Blackbox buffer...")
	
	ordered := make([]ForensicEvent, 0, b.count)
	start := 0
	if b.count == maxBufferSize {
		start = b.head
	}
	for i := 0; i < b.count; i++ {
		idx := (start + i) % maxBufferSize
		ordered = append(ordered, b.events[idx])
	}

	data, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal events: %v", err)
	}

	filename := fmt.Sprintf("forensic_dump_%d.json", time.Now().Unix())
	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Fatalf("Failed to write dump: %v", err)
	}

	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	log.Printf("✅ Forensic data rescued and dumped to: %s", filename)
	log.Printf("🔒 Cryptographic Evidence Hash (SHA-256): %s", hashStr)
	// In Phase 4, this file would be POSTed to the remote vault S3 bucket here.
}

// -------------------------------------------------------------------
// MAIN EXECUTION
// -------------------------------------------------------------------
func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock:", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.BpfProg, nil)
	if err != nil {
		log.Fatalf("Failed to open tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("FTM Sidecar attached. Monitoring Target Pod...")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	blackbox := NewBlackboxBuffer()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-stopper
		rd.Close()
		blackbox.DumpAndHash() // Flush before Pod dies
		os.Exit(0)
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		commandName := string(bytes.TrimRight(event.Comm[:], "\x00"))
		fEvent := ForensicEvent{
			Timestamp: time.Now().Format(time.RFC3339Nano),
			PID:       event.Pid,
			Command:   commandName,
		}
		
		blackbox.Add(fEvent)
	}
}
