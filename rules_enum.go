// Code generated by go-enum DO NOT EDIT.
// Version:
// Revision:
// Build Date:
// Built By:

package main

import (
	"errors"
	"fmt"
)

const (
	// EnumerationScopeShareEnumeration is a EnumerationScope of type ShareEnumeration.
	EnumerationScopeShareEnumeration EnumerationScope = iota
	// EnumerationScopeDirectoryEnumeration is a EnumerationScope of type DirectoryEnumeration.
	EnumerationScopeDirectoryEnumeration
	// EnumerationScopeFileEnumeration is a EnumerationScope of type FileEnumeration.
	EnumerationScopeFileEnumeration
	// EnumerationScopeContentsEnumeration is a EnumerationScope of type ContentsEnumeration.
	EnumerationScopeContentsEnumeration
	// EnumerationScopePostMatch is a EnumerationScope of type PostMatch.
	EnumerationScopePostMatch
)

var ErrInvalidEnumerationScope = errors.New("not a valid EnumerationScope")

const _EnumerationScopeName = "ShareEnumerationDirectoryEnumerationFileEnumerationContentsEnumerationPostMatch"

var _EnumerationScopeMap = map[EnumerationScope]string{
	EnumerationScopeShareEnumeration:     _EnumerationScopeName[0:16],
	EnumerationScopeDirectoryEnumeration: _EnumerationScopeName[16:36],
	EnumerationScopeFileEnumeration:      _EnumerationScopeName[36:51],
	EnumerationScopeContentsEnumeration:  _EnumerationScopeName[51:70],
	EnumerationScopePostMatch:            _EnumerationScopeName[70:79],
}

// String implements the Stringer interface.
func (x EnumerationScope) String() string {
	if str, ok := _EnumerationScopeMap[x]; ok {
		return str
	}
	return fmt.Sprintf("EnumerationScope(%d)", x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x EnumerationScope) IsValid() bool {
	_, ok := _EnumerationScopeMap[x]
	return ok
}

var _EnumerationScopeValue = map[string]EnumerationScope{
	_EnumerationScopeName[0:16]:  EnumerationScopeShareEnumeration,
	_EnumerationScopeName[16:36]: EnumerationScopeDirectoryEnumeration,
	_EnumerationScopeName[36:51]: EnumerationScopeFileEnumeration,
	_EnumerationScopeName[51:70]: EnumerationScopeContentsEnumeration,
	_EnumerationScopeName[70:79]: EnumerationScopePostMatch,
}

// ParseEnumerationScope attempts to convert a string to a EnumerationScope.
func ParseEnumerationScope(name string) (EnumerationScope, error) {
	if x, ok := _EnumerationScopeValue[name]; ok {
		return x, nil
	}
	return EnumerationScope(0), fmt.Errorf("%s is %w", name, ErrInvalidEnumerationScope)
}

// MarshalText implements the text marshaller method.
func (x EnumerationScope) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *EnumerationScope) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseEnumerationScope(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

const (
	// MatchActionDiscard is a MatchAction of type Discard.
	MatchActionDiscard MatchAction = iota
	// MatchActionSendToNextScope is a MatchAction of type SendToNextScope.
	MatchActionSendToNextScope
	// MatchActionSnaffle is a MatchAction of type Snaffle.
	MatchActionSnaffle
	// MatchActionRelay is a MatchAction of type Relay.
	MatchActionRelay
	// MatchActionCheckForKeys is a MatchAction of type CheckForKeys.
	MatchActionCheckForKeys
	// MatchActionEnterArchive is a MatchAction of type EnterArchive.
	MatchActionEnterArchive
)

var ErrInvalidMatchAction = errors.New("not a valid MatchAction")

const _MatchActionName = "DiscardSendToNextScopeSnaffleRelayCheckForKeysEnterArchive"

var _MatchActionMap = map[MatchAction]string{
	MatchActionDiscard:         _MatchActionName[0:7],
	MatchActionSendToNextScope: _MatchActionName[7:22],
	MatchActionSnaffle:         _MatchActionName[22:29],
	MatchActionRelay:           _MatchActionName[29:34],
	MatchActionCheckForKeys:    _MatchActionName[34:46],
	MatchActionEnterArchive:    _MatchActionName[46:58],
}

// String implements the Stringer interface.
func (x MatchAction) String() string {
	if str, ok := _MatchActionMap[x]; ok {
		return str
	}
	return fmt.Sprintf("MatchAction(%d)", x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x MatchAction) IsValid() bool {
	_, ok := _MatchActionMap[x]
	return ok
}

var _MatchActionValue = map[string]MatchAction{
	_MatchActionName[0:7]:   MatchActionDiscard,
	_MatchActionName[7:22]:  MatchActionSendToNextScope,
	_MatchActionName[22:29]: MatchActionSnaffle,
	_MatchActionName[29:34]: MatchActionRelay,
	_MatchActionName[34:46]: MatchActionCheckForKeys,
	_MatchActionName[46:58]: MatchActionEnterArchive,
}

// ParseMatchAction attempts to convert a string to a MatchAction.
func ParseMatchAction(name string) (MatchAction, error) {
	if x, ok := _MatchActionValue[name]; ok {
		return x, nil
	}
	return MatchAction(0), fmt.Errorf("%s is %w", name, ErrInvalidMatchAction)
}

// MarshalText implements the text marshaller method.
func (x MatchAction) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *MatchAction) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseMatchAction(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

const (
	// MatchListTypeExact is a MatchListType of type Exact.
	MatchListTypeExact MatchListType = iota
	// MatchListTypeContains is a MatchListType of type Contains.
	MatchListTypeContains
	// MatchListTypeRegex is a MatchListType of type Regex.
	MatchListTypeRegex
	// MatchListTypeEndsWith is a MatchListType of type EndsWith.
	MatchListTypeEndsWith
	// MatchListTypeStartsWith is a MatchListType of type StartsWith.
	MatchListTypeStartsWith
)

var ErrInvalidMatchListType = errors.New("not a valid MatchListType")

const _MatchListTypeName = "ExactContainsRegexEndsWithStartsWith"

var _MatchListTypeMap = map[MatchListType]string{
	MatchListTypeExact:      _MatchListTypeName[0:5],
	MatchListTypeContains:   _MatchListTypeName[5:13],
	MatchListTypeRegex:      _MatchListTypeName[13:18],
	MatchListTypeEndsWith:   _MatchListTypeName[18:26],
	MatchListTypeStartsWith: _MatchListTypeName[26:36],
}

// String implements the Stringer interface.
func (x MatchListType) String() string {
	if str, ok := _MatchListTypeMap[x]; ok {
		return str
	}
	return fmt.Sprintf("MatchListType(%d)", x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x MatchListType) IsValid() bool {
	_, ok := _MatchListTypeMap[x]
	return ok
}

var _MatchListTypeValue = map[string]MatchListType{
	_MatchListTypeName[0:5]:   MatchListTypeExact,
	_MatchListTypeName[5:13]:  MatchListTypeContains,
	_MatchListTypeName[13:18]: MatchListTypeRegex,
	_MatchListTypeName[18:26]: MatchListTypeEndsWith,
	_MatchListTypeName[26:36]: MatchListTypeStartsWith,
}

// ParseMatchListType attempts to convert a string to a MatchListType.
func ParseMatchListType(name string) (MatchListType, error) {
	if x, ok := _MatchListTypeValue[name]; ok {
		return x, nil
	}
	return MatchListType(0), fmt.Errorf("%s is %w", name, ErrInvalidMatchListType)
}

// MarshalText implements the text marshaller method.
func (x MatchListType) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *MatchListType) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseMatchListType(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

const (
	// MatchLocShareName is a MatchLoc of type ShareName.
	MatchLocShareName MatchLoc = iota
	// MatchLocFilePath is a MatchLoc of type FilePath.
	MatchLocFilePath
	// MatchLocFileName is a MatchLoc of type FileName.
	MatchLocFileName
	// MatchLocFileExtension is a MatchLoc of type FileExtension.
	MatchLocFileExtension
	// MatchLocFileContentAsString is a MatchLoc of type FileContentAsString.
	MatchLocFileContentAsString
	// MatchLocFileContentAsBytes is a MatchLoc of type FileContentAsBytes.
	MatchLocFileContentAsBytes
	// MatchLocFileLength is a MatchLoc of type FileLength.
	MatchLocFileLength
	// MatchLocFileMD5 is a MatchLoc of type FileMD5.
	MatchLocFileMD5
)

var ErrInvalidMatchLoc = errors.New("not a valid MatchLoc")

const _MatchLocName = "ShareNameFilePathFileNameFileExtensionFileContentAsStringFileContentAsBytesFileLengthFileMD5"

var _MatchLocMap = map[MatchLoc]string{
	MatchLocShareName:           _MatchLocName[0:9],
	MatchLocFilePath:            _MatchLocName[9:17],
	MatchLocFileName:            _MatchLocName[17:25],
	MatchLocFileExtension:       _MatchLocName[25:38],
	MatchLocFileContentAsString: _MatchLocName[38:57],
	MatchLocFileContentAsBytes:  _MatchLocName[57:75],
	MatchLocFileLength:          _MatchLocName[75:85],
	MatchLocFileMD5:             _MatchLocName[85:92],
}

// String implements the Stringer interface.
func (x MatchLoc) String() string {
	if str, ok := _MatchLocMap[x]; ok {
		return str
	}
	return fmt.Sprintf("MatchLoc(%d)", x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x MatchLoc) IsValid() bool {
	_, ok := _MatchLocMap[x]
	return ok
}

var _MatchLocValue = map[string]MatchLoc{
	_MatchLocName[0:9]:   MatchLocShareName,
	_MatchLocName[9:17]:  MatchLocFilePath,
	_MatchLocName[17:25]: MatchLocFileName,
	_MatchLocName[25:38]: MatchLocFileExtension,
	_MatchLocName[38:57]: MatchLocFileContentAsString,
	_MatchLocName[57:75]: MatchLocFileContentAsBytes,
	_MatchLocName[75:85]: MatchLocFileLength,
	_MatchLocName[85:92]: MatchLocFileMD5,
}

// ParseMatchLoc attempts to convert a string to a MatchLoc.
func ParseMatchLoc(name string) (MatchLoc, error) {
	if x, ok := _MatchLocValue[name]; ok {
		return x, nil
	}
	return MatchLoc(0), fmt.Errorf("%s is %w", name, ErrInvalidMatchLoc)
}

// MarshalText implements the text marshaller method.
func (x MatchLoc) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *MatchLoc) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseMatchLoc(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}

const (
	// TriageBlack is a Triage of type Black.
	TriageBlack Triage = iota
	// TriageGreen is a Triage of type Green.
	TriageGreen
	// TriageYellow is a Triage of type Yellow.
	TriageYellow
	// TriageRed is a Triage of type Red.
	TriageRed
	// TriageGray is a Triage of type Gray.
	TriageGray
)

var ErrInvalidTriage = errors.New("not a valid Triage")

const _TriageName = "BlackGreenYellowRedGray"

var _TriageMap = map[Triage]string{
	TriageBlack:  _TriageName[0:5],
	TriageGreen:  _TriageName[5:10],
	TriageYellow: _TriageName[10:16],
	TriageRed:    _TriageName[16:19],
	TriageGray:   _TriageName[19:23],
}

// String implements the Stringer interface.
func (x Triage) String() string {
	if str, ok := _TriageMap[x]; ok {
		return str
	}
	return fmt.Sprintf("Triage(%d)", x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x Triage) IsValid() bool {
	_, ok := _TriageMap[x]
	return ok
}

var _TriageValue = map[string]Triage{
	_TriageName[0:5]:   TriageBlack,
	_TriageName[5:10]:  TriageGreen,
	_TriageName[10:16]: TriageYellow,
	_TriageName[16:19]: TriageRed,
	_TriageName[19:23]: TriageGray,
}

// ParseTriage attempts to convert a string to a Triage.
func ParseTriage(name string) (Triage, error) {
	if x, ok := _TriageValue[name]; ok {
		return x, nil
	}
	return Triage(0), fmt.Errorf("%s is %w", name, ErrInvalidTriage)
}

// MarshalText implements the text marshaller method.
func (x Triage) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *Triage) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseTriage(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}
