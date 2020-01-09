package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

type LogInspector struct {
	api  *client.Client
	busy bool
}

func newLogsInspector() *LogInspector {
	c, err := client.NewEnvClient()
	if err != nil {
		log.Fatal(err)
	}
	return &LogInspector{
		api: c,
	}
}

func (inspector LogInspector) renderLogs(ids []string, writer io.Writer) {
	if inspector.busy {
		fmt.Fprintln(writer, "another logs request is in progress")
		return
	}

	inspector.busy = true
	defer func() {
		inspector.busy = false
	}()

	opts := types.ContainerLogsOptions{
		Details:    false,
		Timestamps: true,
		Tail:       "1000",
		ShowStdout: true,
		ShowStderr: true,
	}

	wg := sync.WaitGroup{}
	wg.Add(len(ids))

	buf := bytes.NewBuffer(nil)

	for _, id := range ids {
		go func(id string) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			reader, err := inspector.api.ContainerLogs(ctx, id, opts)
			if err != nil {
				fmt.Fprintf(writer, "container id=%q logs read failed: %s\n", id, err)
				return
			}
			defer reader.Close()

			if _, err := stdcopy.StdCopy(buf, buf, reader); err != nil {
				fmt.Fprintf(writer, "container id=%q stdcopy failed: %s\n", id, err)
			}
		}(id)
	}

	wg.Wait()

	writer.Write(buf.Bytes())
}
