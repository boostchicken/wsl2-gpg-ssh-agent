package manager

import (
	"errors"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var cachedServiceManager *mgr.Mgr

func serviceManager() (*mgr.Mgr, error) {
	if cachedServiceManager != nil {
		return cachedServiceManager, nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	cachedServiceManager = m
	return cachedServiceManager, nil
}

var ErrManagerAlreadyRunning = errors.New("wsl2-ssh-pageant already installed and running")

func InstallService(serviceName string, path string, serviceConfig mgr.Config, args ...string) []error {
	var errs []error
	m, err := serviceManager()
	if err != nil {
		errs = append(errs, err)
		return errs
	}
	_, err = os.Stat(path)
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errs
	}

	// TODO: Do we want to bail if executable isn't being run from the right location?

	service, err := m.OpenService(serviceName)
	defer func(service *mgr.Service) {
		err := service.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}(service)
	if err == nil {
		status, err := service.Query()
		if err != nil {
			return append(errs, err)
		}
		if status.State != svc.Stopped {
			return append(errs, ErrManagerAlreadyRunning)
		}
		err = service.Delete()
		if err != nil {
			return append(errs, err)
		}
		for {
			service, err = m.OpenService(serviceName)
			if err != nil {
				break
			}
			errs = append(errs, service.Close())
			time.Sleep(time.Second / 3)
		}
	}

	service, err = m.CreateService(serviceName, path, serviceConfig, args...)
	if err != nil {
		errs = append(errs, err)
	}
	err = service.Start()
	if err != nil {
		errs = append(errs, err)
		log.Fatalln("Unable to start server", err)
	}
	return errs
}

func UnInstallPageant() []error {
	var errs []error
	m, err := serviceManager()
	if err != nil {
		return append(errs, err)
	}
	serviceName := "wsl2-ssh-pageant"
	service, err := m.OpenService(serviceName)
	if err != nil {
		return append(errs, err)
	}
	_, err = service.Control(svc.Stop)
	if err != nil {
		errs = append(errs, err)
	}
	err = service.Delete()
	err2 := service.Close()
	if err != nil {
		errs = append(errs, err)
	}
	if err2 != nil {
		return append(errs, err2)
	}
	return errs
}
