package rollup

import (
	"context"
	"errors"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

var ErrInvalidWindow = errors.New("invalid rollup refresh window")

type Repository interface {
	RefreshUsageHourly(ctx context.Context, win repository.RollupRefreshWindow) error
	RefreshAccessHourly(ctx context.Context, win repository.RollupRefreshWindow) error
}

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Refresh(ctx context.Context, win repository.RollupRefreshWindow) error {
	if s == nil || s.repo == nil || strings.TrimSpace(win.TenantID) == "" || !win.From.Before(win.To) {
		return ErrInvalidWindow
	}
	if err := s.repo.RefreshUsageHourly(ctx, win); err != nil {
		return err
	}
	return s.repo.RefreshAccessHourly(ctx, win)
}
