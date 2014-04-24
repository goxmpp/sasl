package md5

import "fmt"

type fieldMapper map[string]interface{}

func newFieldMapper() fieldMapper {
	return make(map[string]interface{})
}

func (fm fieldMapper) Add(name string, link interface{}) {
	fm[name] = link
}

func (fm fieldMapper) Set(name string, value []byte) error {
	if field, ok := fm[name]; ok {
		*(field.(*[]byte)) = value
		return nil
	}
	return fmt.Errorf("Unknown parameter '%s' provided", name)
}
