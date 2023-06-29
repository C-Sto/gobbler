package main

import (
	"embed"
	"io"
	"io/fs"
	"log"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed Rules/*
var snaffrules embed.FS

func (g *gobbler) loadRules() error {
	e := fs.WalkDir(snaffrules, ".", g.ruleLoader)
	if e != nil {
		log.Fatal(e)
	}
	//tmprules should now be populated
	if g.ruleMap == nil {
		g.ruleMap = map[string]*ClassifierRule{}
	}

	for i, rule := range g.tmprules.ClassifierRules {
		//add ref to gobbler for global scope crimes
		g.tmprules.ClassifierRules[i].gob = g
		//check for dupes
		if _, ok := g.ruleMap[strings.ToLower(rule.RuleName)]; ok {
			log.Fatal("duplicate rules:", rule.RuleName)
		}
		//set up the regexes
		for _, wr := range g.tmprules.ClassifierRules[i].WordList {
			//fix the rule that is too big :tm:
			wr = strings.Replace(wr, "{3,2000}", "{3,1000}", -1)

			switch rule.WordListType {
			case MatchListTypeContains:
				fallthrough //same same for contains/regex
			case MatchListTypeRegex:
				//do nothing - we good
			case MatchListTypeEndsWith:
				wr = wr + "$"
			case MatchListTypeStartsWith:
				wr = "^" + wr
			case MatchListTypeExact:
				wr = "^" + wr + "$"
			}
			//set case insensitive
			wr = "(?i)" + wr

			r, err := regexp.Compile(wr)
			if err != nil {
				log.Fatal(err)
			}
			g.tmprules.ClassifierRules[i].regexes = append(g.tmprules.ClassifierRules[i].regexes, r)
		}

		//populate map
		g.ruleMap[strings.ToLower(rule.RuleName)] = &g.tmprules.ClassifierRules[i]
		//sort into buckets
		switch rule.EnumerationScope {
		case EnumerationScopeShareEnumeration:
			g.ShareClass.ClassifierRules = append(g.ShareClass.ClassifierRules, g.tmprules.ClassifierRules[i])
		case EnumerationScopeDirectoryEnumeration:
			g.PathClassifiers.ClassifierRules = append(g.PathClassifiers.ClassifierRules, g.tmprules.ClassifierRules[i])
		case EnumerationScopeFileEnumeration:
			if rule.MatchAction == MatchActionDiscard {
				g.FileDiscard.ClassifierRules = append(g.FileDiscard.ClassifierRules, g.tmprules.ClassifierRules[i])
			} else {
				g.FileClassifiers.ClassifierRules = append(g.FileClassifiers.ClassifierRules, g.tmprules.ClassifierRules[i])
			}
		case EnumerationScopeContentsEnumeration:
			g.ContentsClass.ClassifierRules = append(g.ContentsClass.ClassifierRules, g.tmprules.ClassifierRules[i])
		case EnumerationScopePostMatch:
			g.PostMatchClass.ClassifierRules = append(g.PostMatchClass.ClassifierRules, g.tmprules.ClassifierRules[i])
		}
	}

	return e
}

func (g *gobbler) ruleLoader(path string, d fs.DirEntry, err error) error {
	//log.Println(path)
	var tmprule SnaffRules
	if d.Type().IsDir() {
		return nil
	}
	f, e := snaffrules.Open(path)
	if e != nil {
		return e
	}
	datab, e := io.ReadAll(f)
	if e != nil {
		return e
	}
	_, e = toml.Decode(string(datab), &tmprule)
	if e != nil {
		return e
	}
	g.tmprules.ClassifierRules = append(g.tmprules.ClassifierRules, tmprule.ClassifierRules...)
	return nil

}

type SnaffRules struct {
	ClassifierRules []ClassifierRule `toml:"ClassifierRules"`
}

type ClassifierRule struct {
	EnumerationScope EnumerationScope `toml:"EnumerationScope"`
	RuleName         string           `toml:"RuleName"`
	MatchAction      MatchAction      `toml:"MatchAction"`
	RelayTargets     []string         `toml:"RelayTargets,omitempty"`
	Description      string           `toml:"Description"`
	MatchLocation    MatchLoc         `toml:"MatchLocation"`
	WordListType     MatchListType    `toml:"WordListType"`
	MatchLength      int              `toml:"MatchLength"`
	WordList         []string         `toml:"WordList"`
	Triage           Triage           `toml:"Triage"`

	regexes []*regexp.Regexp

	gob *gobbler
}

// ENUM(ShareEnumeration,DirectoryEnumeration,FileEnumeration,ContentsEnumeration,PostMatch)
type EnumerationScope int

// ENUM(ShareName,FilePath,FileName,FileExtension,FileContentAsString,FileContentAsBytes,FileLength,FileMD5)
type MatchLoc int

// ENUM(Exact,Contains,Regex,EndsWith,StartsWith)
type MatchListType int

// ENUM(Discard,SendToNextScope,Snaffle,Relay,CheckForKeys,EnterArchive)
type MatchAction int

// ENUM(Black,Green,Yellow,Red,Gray)
type Triage int

//go:generate go-enum --marshal
