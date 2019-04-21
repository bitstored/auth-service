package service

type Identity struct {
	UserID    string
	FistName  string
	LastName  string
	IsAdmin   bool
	IsBlocked bool
}

func (s *AuthService) GetIdentityByID(uid string) (*Identity, error) {
	return nil, nil
}
