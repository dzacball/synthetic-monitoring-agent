// Code generated by "enumer -type=MultiHttpEntryAssertionType,MultiHttpEntryAssertionSubjectVariant,MultiHttpEntryAssertionConditionVariant,MultiHttpEntryVariableType -trimprefix=MultiHttpEntryAssertionType_,MultiHttpEntryAssertionSubjectVariant_,MultiHttpEntryAssertionConditionVariant_,MultiHttpEntryVariableType_ -transform=upper -output=multihttp_string.go"; DO NOT EDIT.

package synthetic_monitoring

import (
	"fmt"
	"strings"
)

const _MultiHttpEntryAssertionTypeName = "TEXTJSON_PATH_VALUEJSON_PATH_ASSERTIONREGEX_ASSERTION"

var _MultiHttpEntryAssertionTypeIndex = [...]uint8{0, 4, 19, 38, 53}

const _MultiHttpEntryAssertionTypeLowerName = "textjson_path_valuejson_path_assertionregex_assertion"

func (i MultiHttpEntryAssertionType) String() string {
	if i < 0 || i >= MultiHttpEntryAssertionType(len(_MultiHttpEntryAssertionTypeIndex)-1) {
		return fmt.Sprintf("MultiHttpEntryAssertionType(%d)", i)
	}
	return _MultiHttpEntryAssertionTypeName[_MultiHttpEntryAssertionTypeIndex[i]:_MultiHttpEntryAssertionTypeIndex[i+1]]
}

// An "invalid array index" compiler error signifies that the constant values have changed.
// Re-run the stringer command to generate them again.
func _MultiHttpEntryAssertionTypeNoOp() {
	var x [1]struct{}
	_ = x[MultiHttpEntryAssertionType_TEXT-(0)]
	_ = x[MultiHttpEntryAssertionType_JSON_PATH_VALUE-(1)]
	_ = x[MultiHttpEntryAssertionType_JSON_PATH_ASSERTION-(2)]
	_ = x[MultiHttpEntryAssertionType_REGEX_ASSERTION-(3)]
}

var _MultiHttpEntryAssertionTypeValues = []MultiHttpEntryAssertionType{MultiHttpEntryAssertionType_TEXT, MultiHttpEntryAssertionType_JSON_PATH_VALUE, MultiHttpEntryAssertionType_JSON_PATH_ASSERTION, MultiHttpEntryAssertionType_REGEX_ASSERTION}

var _MultiHttpEntryAssertionTypeNameToValueMap = map[string]MultiHttpEntryAssertionType{
	_MultiHttpEntryAssertionTypeName[0:4]:        MultiHttpEntryAssertionType_TEXT,
	_MultiHttpEntryAssertionTypeLowerName[0:4]:   MultiHttpEntryAssertionType_TEXT,
	_MultiHttpEntryAssertionTypeName[4:19]:       MultiHttpEntryAssertionType_JSON_PATH_VALUE,
	_MultiHttpEntryAssertionTypeLowerName[4:19]:  MultiHttpEntryAssertionType_JSON_PATH_VALUE,
	_MultiHttpEntryAssertionTypeName[19:38]:      MultiHttpEntryAssertionType_JSON_PATH_ASSERTION,
	_MultiHttpEntryAssertionTypeLowerName[19:38]: MultiHttpEntryAssertionType_JSON_PATH_ASSERTION,
	_MultiHttpEntryAssertionTypeName[38:53]:      MultiHttpEntryAssertionType_REGEX_ASSERTION,
	_MultiHttpEntryAssertionTypeLowerName[38:53]: MultiHttpEntryAssertionType_REGEX_ASSERTION,
}

var _MultiHttpEntryAssertionTypeNames = []string{
	_MultiHttpEntryAssertionTypeName[0:4],
	_MultiHttpEntryAssertionTypeName[4:19],
	_MultiHttpEntryAssertionTypeName[19:38],
	_MultiHttpEntryAssertionTypeName[38:53],
}

// MultiHttpEntryAssertionTypeString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func MultiHttpEntryAssertionTypeString(s string) (MultiHttpEntryAssertionType, error) {
	if val, ok := _MultiHttpEntryAssertionTypeNameToValueMap[s]; ok {
		return val, nil
	}

	if val, ok := _MultiHttpEntryAssertionTypeNameToValueMap[strings.ToLower(s)]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to MultiHttpEntryAssertionType values", s)
}

// MultiHttpEntryAssertionTypeValues returns all values of the enum
func MultiHttpEntryAssertionTypeValues() []MultiHttpEntryAssertionType {
	return _MultiHttpEntryAssertionTypeValues
}

// MultiHttpEntryAssertionTypeStrings returns a slice of all String values of the enum
func MultiHttpEntryAssertionTypeStrings() []string {
	strs := make([]string, len(_MultiHttpEntryAssertionTypeNames))
	copy(strs, _MultiHttpEntryAssertionTypeNames)
	return strs
}

// IsAMultiHttpEntryAssertionType returns "true" if the value is listed in the enum definition. "false" otherwise
func (i MultiHttpEntryAssertionType) IsAMultiHttpEntryAssertionType() bool {
	for _, v := range _MultiHttpEntryAssertionTypeValues {
		if i == v {
			return true
		}
	}
	return false
}

const _MultiHttpEntryAssertionSubjectVariantName = "DEFAULT_SUBJECTRESPONSE_HEADERSHTTP_STATUS_CODERESPONSE_BODY"

var _MultiHttpEntryAssertionSubjectVariantIndex = [...]uint8{0, 15, 31, 47, 60}

const _MultiHttpEntryAssertionSubjectVariantLowerName = "default_subjectresponse_headershttp_status_coderesponse_body"

func (i MultiHttpEntryAssertionSubjectVariant) String() string {
	if i < 0 || i >= MultiHttpEntryAssertionSubjectVariant(len(_MultiHttpEntryAssertionSubjectVariantIndex)-1) {
		return fmt.Sprintf("MultiHttpEntryAssertionSubjectVariant(%d)", i)
	}
	return _MultiHttpEntryAssertionSubjectVariantName[_MultiHttpEntryAssertionSubjectVariantIndex[i]:_MultiHttpEntryAssertionSubjectVariantIndex[i+1]]
}

// An "invalid array index" compiler error signifies that the constant values have changed.
// Re-run the stringer command to generate them again.
func _MultiHttpEntryAssertionSubjectVariantNoOp() {
	var x [1]struct{}
	_ = x[MultiHttpEntryAssertionSubjectVariant_DEFAULT_SUBJECT-(0)]
	_ = x[MultiHttpEntryAssertionSubjectVariant_RESPONSE_HEADERS-(1)]
	_ = x[MultiHttpEntryAssertionSubjectVariant_HTTP_STATUS_CODE-(2)]
	_ = x[MultiHttpEntryAssertionSubjectVariant_RESPONSE_BODY-(3)]
}

var _MultiHttpEntryAssertionSubjectVariantValues = []MultiHttpEntryAssertionSubjectVariant{MultiHttpEntryAssertionSubjectVariant_DEFAULT_SUBJECT, MultiHttpEntryAssertionSubjectVariant_RESPONSE_HEADERS, MultiHttpEntryAssertionSubjectVariant_HTTP_STATUS_CODE, MultiHttpEntryAssertionSubjectVariant_RESPONSE_BODY}

var _MultiHttpEntryAssertionSubjectVariantNameToValueMap = map[string]MultiHttpEntryAssertionSubjectVariant{
	_MultiHttpEntryAssertionSubjectVariantName[0:15]:       MultiHttpEntryAssertionSubjectVariant_DEFAULT_SUBJECT,
	_MultiHttpEntryAssertionSubjectVariantLowerName[0:15]:  MultiHttpEntryAssertionSubjectVariant_DEFAULT_SUBJECT,
	_MultiHttpEntryAssertionSubjectVariantName[15:31]:      MultiHttpEntryAssertionSubjectVariant_RESPONSE_HEADERS,
	_MultiHttpEntryAssertionSubjectVariantLowerName[15:31]: MultiHttpEntryAssertionSubjectVariant_RESPONSE_HEADERS,
	_MultiHttpEntryAssertionSubjectVariantName[31:47]:      MultiHttpEntryAssertionSubjectVariant_HTTP_STATUS_CODE,
	_MultiHttpEntryAssertionSubjectVariantLowerName[31:47]: MultiHttpEntryAssertionSubjectVariant_HTTP_STATUS_CODE,
	_MultiHttpEntryAssertionSubjectVariantName[47:60]:      MultiHttpEntryAssertionSubjectVariant_RESPONSE_BODY,
	_MultiHttpEntryAssertionSubjectVariantLowerName[47:60]: MultiHttpEntryAssertionSubjectVariant_RESPONSE_BODY,
}

var _MultiHttpEntryAssertionSubjectVariantNames = []string{
	_MultiHttpEntryAssertionSubjectVariantName[0:15],
	_MultiHttpEntryAssertionSubjectVariantName[15:31],
	_MultiHttpEntryAssertionSubjectVariantName[31:47],
	_MultiHttpEntryAssertionSubjectVariantName[47:60],
}

// MultiHttpEntryAssertionSubjectVariantString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func MultiHttpEntryAssertionSubjectVariantString(s string) (MultiHttpEntryAssertionSubjectVariant, error) {
	if val, ok := _MultiHttpEntryAssertionSubjectVariantNameToValueMap[s]; ok {
		return val, nil
	}

	if val, ok := _MultiHttpEntryAssertionSubjectVariantNameToValueMap[strings.ToLower(s)]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to MultiHttpEntryAssertionSubjectVariant values", s)
}

// MultiHttpEntryAssertionSubjectVariantValues returns all values of the enum
func MultiHttpEntryAssertionSubjectVariantValues() []MultiHttpEntryAssertionSubjectVariant {
	return _MultiHttpEntryAssertionSubjectVariantValues
}

// MultiHttpEntryAssertionSubjectVariantStrings returns a slice of all String values of the enum
func MultiHttpEntryAssertionSubjectVariantStrings() []string {
	strs := make([]string, len(_MultiHttpEntryAssertionSubjectVariantNames))
	copy(strs, _MultiHttpEntryAssertionSubjectVariantNames)
	return strs
}

// IsAMultiHttpEntryAssertionSubjectVariant returns "true" if the value is listed in the enum definition. "false" otherwise
func (i MultiHttpEntryAssertionSubjectVariant) IsAMultiHttpEntryAssertionSubjectVariant() bool {
	for _, v := range _MultiHttpEntryAssertionSubjectVariantValues {
		if i == v {
			return true
		}
	}
	return false
}

const _MultiHttpEntryAssertionConditionVariantName = "DEFAULT_CONDITIONNOT_CONTAINSEQUALSSTARTS_WITHENDS_WITHTYPE_OFCONTAINS"

var _MultiHttpEntryAssertionConditionVariantIndex = [...]uint8{0, 17, 29, 35, 46, 55, 62, 70}

const _MultiHttpEntryAssertionConditionVariantLowerName = "default_conditionnot_containsequalsstarts_withends_withtype_ofcontains"

func (i MultiHttpEntryAssertionConditionVariant) String() string {
	if i < 0 || i >= MultiHttpEntryAssertionConditionVariant(len(_MultiHttpEntryAssertionConditionVariantIndex)-1) {
		return fmt.Sprintf("MultiHttpEntryAssertionConditionVariant(%d)", i)
	}
	return _MultiHttpEntryAssertionConditionVariantName[_MultiHttpEntryAssertionConditionVariantIndex[i]:_MultiHttpEntryAssertionConditionVariantIndex[i+1]]
}

// An "invalid array index" compiler error signifies that the constant values have changed.
// Re-run the stringer command to generate them again.
func _MultiHttpEntryAssertionConditionVariantNoOp() {
	var x [1]struct{}
	_ = x[MultiHttpEntryAssertionConditionVariant_DEFAULT_CONDITION-(0)]
	_ = x[MultiHttpEntryAssertionConditionVariant_NOT_CONTAINS-(1)]
	_ = x[MultiHttpEntryAssertionConditionVariant_EQUALS-(2)]
	_ = x[MultiHttpEntryAssertionConditionVariant_STARTS_WITH-(3)]
	_ = x[MultiHttpEntryAssertionConditionVariant_ENDS_WITH-(4)]
	_ = x[MultiHttpEntryAssertionConditionVariant_TYPE_OF-(5)]
	_ = x[MultiHttpEntryAssertionConditionVariant_CONTAINS-(6)]
}

var _MultiHttpEntryAssertionConditionVariantValues = []MultiHttpEntryAssertionConditionVariant{MultiHttpEntryAssertionConditionVariant_DEFAULT_CONDITION, MultiHttpEntryAssertionConditionVariant_NOT_CONTAINS, MultiHttpEntryAssertionConditionVariant_EQUALS, MultiHttpEntryAssertionConditionVariant_STARTS_WITH, MultiHttpEntryAssertionConditionVariant_ENDS_WITH, MultiHttpEntryAssertionConditionVariant_TYPE_OF, MultiHttpEntryAssertionConditionVariant_CONTAINS}

var _MultiHttpEntryAssertionConditionVariantNameToValueMap = map[string]MultiHttpEntryAssertionConditionVariant{
	_MultiHttpEntryAssertionConditionVariantName[0:17]:       MultiHttpEntryAssertionConditionVariant_DEFAULT_CONDITION,
	_MultiHttpEntryAssertionConditionVariantLowerName[0:17]:  MultiHttpEntryAssertionConditionVariant_DEFAULT_CONDITION,
	_MultiHttpEntryAssertionConditionVariantName[17:29]:      MultiHttpEntryAssertionConditionVariant_NOT_CONTAINS,
	_MultiHttpEntryAssertionConditionVariantLowerName[17:29]: MultiHttpEntryAssertionConditionVariant_NOT_CONTAINS,
	_MultiHttpEntryAssertionConditionVariantName[29:35]:      MultiHttpEntryAssertionConditionVariant_EQUALS,
	_MultiHttpEntryAssertionConditionVariantLowerName[29:35]: MultiHttpEntryAssertionConditionVariant_EQUALS,
	_MultiHttpEntryAssertionConditionVariantName[35:46]:      MultiHttpEntryAssertionConditionVariant_STARTS_WITH,
	_MultiHttpEntryAssertionConditionVariantLowerName[35:46]: MultiHttpEntryAssertionConditionVariant_STARTS_WITH,
	_MultiHttpEntryAssertionConditionVariantName[46:55]:      MultiHttpEntryAssertionConditionVariant_ENDS_WITH,
	_MultiHttpEntryAssertionConditionVariantLowerName[46:55]: MultiHttpEntryAssertionConditionVariant_ENDS_WITH,
	_MultiHttpEntryAssertionConditionVariantName[55:62]:      MultiHttpEntryAssertionConditionVariant_TYPE_OF,
	_MultiHttpEntryAssertionConditionVariantLowerName[55:62]: MultiHttpEntryAssertionConditionVariant_TYPE_OF,
	_MultiHttpEntryAssertionConditionVariantName[62:70]:      MultiHttpEntryAssertionConditionVariant_CONTAINS,
	_MultiHttpEntryAssertionConditionVariantLowerName[62:70]: MultiHttpEntryAssertionConditionVariant_CONTAINS,
}

var _MultiHttpEntryAssertionConditionVariantNames = []string{
	_MultiHttpEntryAssertionConditionVariantName[0:17],
	_MultiHttpEntryAssertionConditionVariantName[17:29],
	_MultiHttpEntryAssertionConditionVariantName[29:35],
	_MultiHttpEntryAssertionConditionVariantName[35:46],
	_MultiHttpEntryAssertionConditionVariantName[46:55],
	_MultiHttpEntryAssertionConditionVariantName[55:62],
	_MultiHttpEntryAssertionConditionVariantName[62:70],
}

// MultiHttpEntryAssertionConditionVariantString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func MultiHttpEntryAssertionConditionVariantString(s string) (MultiHttpEntryAssertionConditionVariant, error) {
	if val, ok := _MultiHttpEntryAssertionConditionVariantNameToValueMap[s]; ok {
		return val, nil
	}

	if val, ok := _MultiHttpEntryAssertionConditionVariantNameToValueMap[strings.ToLower(s)]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to MultiHttpEntryAssertionConditionVariant values", s)
}

// MultiHttpEntryAssertionConditionVariantValues returns all values of the enum
func MultiHttpEntryAssertionConditionVariantValues() []MultiHttpEntryAssertionConditionVariant {
	return _MultiHttpEntryAssertionConditionVariantValues
}

// MultiHttpEntryAssertionConditionVariantStrings returns a slice of all String values of the enum
func MultiHttpEntryAssertionConditionVariantStrings() []string {
	strs := make([]string, len(_MultiHttpEntryAssertionConditionVariantNames))
	copy(strs, _MultiHttpEntryAssertionConditionVariantNames)
	return strs
}

// IsAMultiHttpEntryAssertionConditionVariant returns "true" if the value is listed in the enum definition. "false" otherwise
func (i MultiHttpEntryAssertionConditionVariant) IsAMultiHttpEntryAssertionConditionVariant() bool {
	for _, v := range _MultiHttpEntryAssertionConditionVariantValues {
		if i == v {
			return true
		}
	}
	return false
}

const _MultiHttpEntryVariableTypeName = "JSON_PATHREGEXCSS_SELECTOR"

var _MultiHttpEntryVariableTypeIndex = [...]uint8{0, 9, 14, 26}

const _MultiHttpEntryVariableTypeLowerName = "json_pathregexcss_selector"

func (i MultiHttpEntryVariableType) String() string {
	if i < 0 || i >= MultiHttpEntryVariableType(len(_MultiHttpEntryVariableTypeIndex)-1) {
		return fmt.Sprintf("MultiHttpEntryVariableType(%d)", i)
	}
	return _MultiHttpEntryVariableTypeName[_MultiHttpEntryVariableTypeIndex[i]:_MultiHttpEntryVariableTypeIndex[i+1]]
}

// An "invalid array index" compiler error signifies that the constant values have changed.
// Re-run the stringer command to generate them again.
func _MultiHttpEntryVariableTypeNoOp() {
	var x [1]struct{}
	_ = x[MultiHttpEntryVariableType_JSON_PATH-(0)]
	_ = x[MultiHttpEntryVariableType_REGEX-(1)]
	_ = x[MultiHttpEntryVariableType_CSS_SELECTOR-(2)]
}

var _MultiHttpEntryVariableTypeValues = []MultiHttpEntryVariableType{MultiHttpEntryVariableType_JSON_PATH, MultiHttpEntryVariableType_REGEX, MultiHttpEntryVariableType_CSS_SELECTOR}

var _MultiHttpEntryVariableTypeNameToValueMap = map[string]MultiHttpEntryVariableType{
	_MultiHttpEntryVariableTypeName[0:9]:        MultiHttpEntryVariableType_JSON_PATH,
	_MultiHttpEntryVariableTypeLowerName[0:9]:   MultiHttpEntryVariableType_JSON_PATH,
	_MultiHttpEntryVariableTypeName[9:14]:       MultiHttpEntryVariableType_REGEX,
	_MultiHttpEntryVariableTypeLowerName[9:14]:  MultiHttpEntryVariableType_REGEX,
	_MultiHttpEntryVariableTypeName[14:26]:      MultiHttpEntryVariableType_CSS_SELECTOR,
	_MultiHttpEntryVariableTypeLowerName[14:26]: MultiHttpEntryVariableType_CSS_SELECTOR,
}

var _MultiHttpEntryVariableTypeNames = []string{
	_MultiHttpEntryVariableTypeName[0:9],
	_MultiHttpEntryVariableTypeName[9:14],
	_MultiHttpEntryVariableTypeName[14:26],
}

// MultiHttpEntryVariableTypeString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func MultiHttpEntryVariableTypeString(s string) (MultiHttpEntryVariableType, error) {
	if val, ok := _MultiHttpEntryVariableTypeNameToValueMap[s]; ok {
		return val, nil
	}

	if val, ok := _MultiHttpEntryVariableTypeNameToValueMap[strings.ToLower(s)]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to MultiHttpEntryVariableType values", s)
}

// MultiHttpEntryVariableTypeValues returns all values of the enum
func MultiHttpEntryVariableTypeValues() []MultiHttpEntryVariableType {
	return _MultiHttpEntryVariableTypeValues
}

// MultiHttpEntryVariableTypeStrings returns a slice of all String values of the enum
func MultiHttpEntryVariableTypeStrings() []string {
	strs := make([]string, len(_MultiHttpEntryVariableTypeNames))
	copy(strs, _MultiHttpEntryVariableTypeNames)
	return strs
}

// IsAMultiHttpEntryVariableType returns "true" if the value is listed in the enum definition. "false" otherwise
func (i MultiHttpEntryVariableType) IsAMultiHttpEntryVariableType() bool {
	for _, v := range _MultiHttpEntryVariableTypeValues {
		if i == v {
			return true
		}
	}
	return false
}
