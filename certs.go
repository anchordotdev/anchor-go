package anchor

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var Certs = make(CertSet)

type CertType int

const (
	Unknown CertType = iota
	AnchorCA
	SubCA
	Leaf
)

type CertInfo struct {
	Algo   x509.PublicKeyAlgorithm
	Name   string
	Serial string
	Type   CertType
}

type CertSet map[CertInfo]*x509.Certificate

func (s CertSet) Append(cert *x509.Certificate) {
	info := CertInfo{
		Algo:   cert.PublicKeyAlgorithm,
		Name:   cert.Subject.CommonName,
		Serial: cert.SerialNumber.Text(16),
		Type:   Leaf,
	}

	switch {
	case cert.IsCA && cert.MaxPathLenZero:
		info.Type = SubCA
	case cert.IsCA:
		info.Type = AnchorCA
	}

	s[info] = cert
}

func (s CertSet) AppendPEM(data string) error {
	buf := []byte(data)

	var block *pem.Block
	for len(buf) > 0 {
		block, buf = pem.Decode(buf)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("anchor: invalid certificate PEM data")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		s.Append(cert)
	}
	return nil
}

func (s CertSet) AddToPool(pool *x509.CertPool) {
	for _, cert := range s {
		pool.AddCert(cert)
	}
}

func (s CertSet) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	s.AddToPool(pool)
	return pool
}

func (s CertSet) Select(fns ...FilterFunc) (CertSet, error) {
	ss := make(CertSet)

	for info, cert := range s {
		ok, err := match(info, cert, fns)
		if err != nil {
			return nil, err
		}
		if ok {
			ss[info] = cert
		}
	}
	return ss, nil
}

func (s CertSet) Find(fns ...FilterFunc) (CertInfo, *x509.Certificate, error) {
	for info, cert := range s {
		ok, err := match(info, cert, fns)
		if err != nil {
			return CertInfo{}, nil, err
		}
		if ok {
			return info, cert, nil
		}
	}
	return CertInfo{}, nil, nil
}

func match(info CertInfo, cert *x509.Certificate, fns []FilterFunc) (bool, error) {
	for _, fn := range fns {
		ok, err := fn(info, cert)
		if !ok || err != nil {
			return ok, err
		}
	}
	return true, nil
}

type FilterFunc func(CertInfo, *x509.Certificate) (bool, error)

func ByAlgo(algo x509.PublicKeyAlgorithm) FilterFunc {
	return func(info CertInfo, _ *x509.Certificate) (bool, error) {
		return info.Algo == algo, nil
	}
}

func ByName(name string) FilterFunc {
	return func(info CertInfo, _ *x509.Certificate) (bool, error) {
		return info.Name == name, nil
	}
}

func BySerial(serial string) FilterFunc {
	return func(info CertInfo, _ *x509.Certificate) (bool, error) {
		return info.Serial == serial, nil
	}
}

func ByType(typ CertType) FilterFunc {
	return func(info CertInfo, _ *x509.Certificate) (bool, error) {
		return info.Type == typ, nil
	}
}
