package main

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func (c *ClassifierRule) ClassifyFile(path string) bool {
	if c.gob == nil {
		log.Fatal("NIL GOB ", c.RuleName)
	}
	//we are approx here https://github.com/SnaffCon/Snaffler/blob/master/SnaffCore/Classifiers/FileClassifier.cs#L23
	stringToMatch := ""

	switch c.MatchLocation {
	case MatchLocFileExtension:
		//stringtoMatch = ""
		stringToMatch = filepath.Ext(path)
	case MatchLocFileName:
		stringToMatch = filepath.Base(path) //should be filename
	case MatchLocFilePath:
		stringToMatch = path
	case MatchLocFileLength:
		//moving this to later, so we can avoid the OS syscall being run too many times
	}

	//handle easy matchers here (not yet reading the file)

	if stringToMatch != "" {
		found, match := c.TextMatch(stringToMatch)
		if !found {
			//do not snaff
			return false
		}

		//determine how to snaff
		//approx here
		//https: //github.com/SnaffCon/Snaffler/blob/master/SnaffCore/Classifiers/FileClassifier.cs#L85
		switch c.MatchAction {
		case MatchActionDiscard:
			return true
		case MatchActionSnaffle:
			//this is a result
			//todo add rule that matched
			c.LogResult(match, path)

		case MatchActionCheckForKeys:
			//do x509 bs
		case MatchActionRelay:
			//this says 'do more snaffles with these other rules now that we know it's interesting'
			//log.Println("RELAY", stringToMatch, c.RelayTargets)
			for _, target := range c.RelayTargets {
				c.gob.ruleMap[strings.ToLower(target)].ClassifyFile(path)
			}

		case MatchActionEnterArchive:
			//todo lol
		}
		return false
	}
	//log.Println(c.RuleName, c.MatchLocation, c.EnumerationScope)
	//we are likely in a rule that requires some sort of high overhead action (like reading content)
	//this check can probs be removed, but it helps for reading
	if c.EnumerationScope == EnumerationScopeContentsEnumeration {
		//get ready to read the file

		switch c.MatchLocation {
		case MatchLocFileContentAsString:
			stat, err := os.Stat(path)
			if err != nil {
				log.Println(err)
				return false
			}
			if stat.Size() > c.gob.maxsize {
				return false
			} //10mb ish
			fullfile, err := os.ReadFile(path)
			if err != nil {
				//probs bad permission
				log.Println(err)
				return false
			}
			found, match := c.TextMatch(string(fullfile))
			if found {
				c.LogResult(match, path)
			}
		case MatchLocFileContentAsBytes:
			//todo
			log.Println("BYTES ME BB", c.RuleName)
		}
	}

	return false
}

func (c *ClassifierRule) TextMatch(s string) (bool, TextResult) {
	ret := TextResult{}
	//approx here https://github.com/SnaffCon/Snaffler/blob/master/SnaffCore/Classifiers/TextClassifier.cs#L9
	for _, pattern := range c.regexes {
		match := pattern.FindString(s)
		if match != "" {
			ret.MatchedStrings = pattern.String()
			ctx := strings.ReplaceAll(getContext(200, s, pattern), "\n", "\\n")
			ctx = strings.ReplaceAll(ctx, "\r", "\\r")
			ret.MatchContext = ctx
		}
	}

	return ret.MatchedStrings != "", ret
}

type TextResult struct {
	MatchedStrings string //regex that made the match
	MatchContext   string //actual match with some extras
}

// triageString, matchedclassifier, canread, canwrite, canmodify, matchedstring, fileSizeString, modifiedStamp, filepath, matchcontext);
func (c *ClassifierRule) LogResult(match TextResult, path string) {
	size := int64(0)
	mode := ""
	time := ""
	stat, err := os.Stat(path)
	if err != nil {
		log.Println("error:", err)
	} else {
		size = stat.Size()
		mode = stat.Mode().String()
		time = stat.ModTime().String()
	}

	logtyp := ""

	log.Printf("[%s] {%s}<%s|%s|%s|%d|%s>(%s)%s",
		logtyp, c.Triage, c.RuleName, mode, match.MatchedStrings, size, time, path, match.MatchContext)
}

func getContext(context int, original string, pattern *regexp.Regexp) string {
	if context == 0 {
		return ""
	}
	if len(original) < context*2 {
		return original
	}

	idx := pattern.FindStringIndex(original)
	if len(idx) < 1 {
		//idk
	}
	pre := subfloor(idx[0], context, 0)

	if len(original) <= pre+(context*2) {
		return original[pre:]
	}

	return original[pre : pre+(context/2)]

}

// subtracts j from i, if the result is below k, return k, otherwise return
func subfloor(i int, j int, k int) int {
	res := i - j
	if res > k {
		return res
	}
	return k
}
