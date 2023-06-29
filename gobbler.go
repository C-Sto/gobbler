package main

import (
	"sync"
)

type gobbler struct {
	tmprules SnaffRules

	FileClassifiers SnaffRules
	FileDiscard     SnaffRules

	PathClassifiers SnaffRules
	PostMatchClass  SnaffRules
	ShareClass      SnaffRules
	ContentsClass   SnaffRules

	ruleMap map[string]*ClassifierRule

	postmatch chan string
	wg        *sync.WaitGroup
	maxsize   int64
}

func NewGobbler() gobbler {
	g := gobbler{
		postmatch: make(chan string, 100), //up to 100 paths can be queued up to wait for a spare worker
		wg:        &sync.WaitGroup{},
		maxsize:   10000000,
	}
	return g
}

func (g *gobbler) startWorkers(n int) {
	//start n post-match workers
	for i := 0; i < n; i++ {
		go g.postmatchScan()
	}
}

func (g *gobbler) postmatchScan() {
	for path := range g.postmatch { //blocks if the chan is empty, loops infinitely until the chan is closed
		//"snaffle" case
		stop := false
		for _, discarder := range g.FileDiscard.ClassifierRules {
			if discarder.ClassifyFile(path) {
				stop = true
				break
			}
		}
		if stop {
			g.wg.Done()
			continue
		}
		for _, fileclass := range g.FileClassifiers.ClassifierRules { //loops over file classifiers
			fileclass.ClassifyFile(path)
		}
		g.wg.Done()
	}
}
