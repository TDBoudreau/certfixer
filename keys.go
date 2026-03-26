package main

import (
	"charm.land/bubbles/v2/key"
)

type pickingKeyMap struct {
	Up   key.Binding
	Down key.Binding
	Back key.Binding
	Open key.Binding
	Help key.Binding
	Quit key.Binding
}

func (k pickingKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Help, k.Quit}
}

func (k pickingKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down},
		{k.Back, k.Open},
		{k.Help, k.Quit},
	}
}

var pickingKeys = pickingKeyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "w"),
		key.WithHelp("↑/w", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "s"),
		key.WithHelp("↓/s", "move down"),
	),
	Back: key.NewBinding(
		key.WithKeys("left", "a"),
		key.WithHelp("←/a", "go back"),
	),
	Open: key.NewBinding(
		key.WithKeys("right", "d", "enter"),
		key.WithHelp("→/d", "open"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
}

type analysisKeyMap struct {
	Up      key.Binding
	Down    key.Binding
	Confirm key.Binding
	Back    key.Binding
	Help    key.Binding
	Quit    key.Binding
}

func (k analysisKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Confirm, k.Back, k.Help}
}

func (k analysisKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down},
		{k.Confirm, k.Back},
		{k.Help, k.Quit},
	}
}

var analysisKeys = analysisKeyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "w", "k"),
		key.WithHelp("↑/w/k", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "s", "j"),
		key.WithHelp("↓/s/j", "move down"),
	),
	Confirm: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "write file"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
}

type doneKeyMap struct {
	Quit key.Binding
}

func (k doneKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Quit}
}

func (k doneKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Quit}}
}

var doneKeys = doneKeyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "enter", "esc", "ctrl+c"),
		key.WithHelp("q/enter", "quit"),
	),
}
