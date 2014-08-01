package oauth2

import (
  "fmt"
  "os"
  "sync"
  "io/ioutil"
  "encoding/json"
)

type Client struct {
  Id          string
  Secret      string
  BaseUri     string
  Description string
}

func (c *Client) String() string {
  return fmt.Sprintf("client %s for %s", c.Id, c.BaseUri)
}

func NewClient(id, secret, uri, des string) *Client {
  return &Client{id, secret, uri, des}
}

type FileClientStore struct {
  filename string
  locker *sync.Mutex
  modtime int64
  m map[string]*Client
}

func NewFileClientStore(filename string) (*FileClientStore, error) {
  f, err := os.Open(filename)
  if err != nil {
    return nil, err
  }
  c, err := ioutil.ReadAll(f)
  if err != nil {
    return nil, err
  }

  err = f.Close()
  if err != nil {
    return nil, err
  }

  m := make(map[string]*Client)
  err = json.Unmarshal(c, &m)
  if err != nil {
    return nil, err
  }
  info, err := os.Stat(filename)
  if err != nil {
    return nil, err
  }
  return &FileClientStore{filename, new(sync.Mutex), info.ModTime().Unix(),
    m}, nil
}

func (s *FileClientStore) saveFile() error {
  c, err := json.Marshal(s.m)
  if err !=nil {
    return err
  }

  f, err := os.Create(s.filename)
  if err != nil {
    return err
  }

  _, err = f.Write(c)
  if err != nil {
    return err
  }

  err = f.Close()
  if err != nil {
    return err
  }

  info, err := os.Stat(s.filename)
  if err != nil {
    return err
  }

  s.modtime = info.ModTime().Unix()
  return nil
}

func (s *FileClientStore) updateMap() error {
  info, err := os.Stat(s.filename)
  if err != nil {
    return err
  }

  if info.ModTime().Unix() > s.modtime {
    f, err := os.Open(s.filename)
    if err != nil {
      return err
    }

    c, err := ioutil.ReadAll(f)
    if err != nil {
      return err
    }

    m := make(map[string]*Client)
    err = json.Unmarshal(c, &m)
    if err != nil {
      return err
    }
    s.m = m
  }
  return nil
}

func (s *FileClientStore) Save(c *Client) (string, error) {
  s.locker.Lock()
  defer s.locker.Unlock()
  err := s.updateMap()
  if err !=nil {
    return "", err
  }

  s.m[c.Id] = c

  err = s.saveFile()
  if err !=nil {
    return "", err
  }
  return c.Id, nil
}

func (s *FileClientStore) Read(id string) (*Client, error) {
  s.locker.Lock()
  defer s.locker.Unlock()
  err := s.updateMap()
  if err !=nil {
    return nil, err
  }
  return s.m[id], nil
}

func (s *FileClientStore) Remove(id string) error {
  s.locker.Lock()
  defer s.locker.Unlock()
  err := s.updateMap()
  if err !=nil {
    return err
  }

  delete(s.m, id)

  err = s.saveFile()
  if err !=nil {
    return err
  }
  return nil
}
