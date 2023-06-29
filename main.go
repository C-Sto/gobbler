package main

import (
	"flag"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func main() {
	starttime := time.Now()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	start := flag.String("i", "./", "where to start your snafs")
	flag.Parse()
	g := gobbler{
		postmatch: make(chan string, 100), //up to 100 paths can be queued up to wait for a spare worker
		wg:        &sync.WaitGroup{},
		maxsize:   10000000,
	}
	g.loadRules()
	g.startWorkers(40)                   //start 40 filescan workers
	filepath.WalkDir(*start, g.treewalk) //will block while we walk all dirs
	g.Wait()
	log.Println("took: ", time.Since(starttime))
}

func (g *gobbler) treewalk(path string, d os.DirEntry, err error) error {
	//treewalker concurrency goes here

	if d.IsDir() {
		if err != nil {
			return fs.SkipDir
		}
		//run dir classifiers
		for _, class := range g.PathClassifiers.ClassifierRules {
			if class.ClassifyFile(path) {
				//all these are discard
				return fs.SkipDir
			}
		}
		return nil
	}

	g.ScanFile(path)

	return nil
}

func (g *gobbler) ScanFile(path string) {
	//pre-match here

	//*hand waving*

	//looks good, snaffle it
	g.wg.Add(1)
	g.postmatch <- path //this will block if all file scanners are working hard
}

func (g *gobbler) Wait() {
	g.wg.Wait()
}
