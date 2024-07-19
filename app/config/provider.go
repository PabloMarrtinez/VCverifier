package config

import (
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
)

// read the config from the config file
func ReadConfig(configFile string) (configuration Configuration, err error) {
	config.WithOptions(config.ParseDefault)
	config.AddDriver(yaml.Driver)
	err = config.LoadFiles(configFile)

	if err != nil {
		return
	}
	config.BindStruct("", &configuration)
	return
}
