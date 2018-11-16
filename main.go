package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2/google"

	"google.golang.org/api/appengine/v1"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "gae_static_ips"
	app.Usage = "github.com/akm/gae_static_ips"
	app.Version = Version

	flags := []cli.Flag{
		cli.StringFlag{
			Name:  "apps-id",
			Usage: "Apps ID (= GCP Project)",
		},
		cli.Int64Flag{
			Name:  "base-priority",
			Value: 8000,
			Usage: "First priority number to update rules for Appengine",
		},
		cli.Int64Flag{
			Name:  "max-priority",
			Value: 8999,
			Usage: "First priority number to update rules for Appengine",
		},
		cli.StringFlag{
			Name:  "comment",
			Value: "by fw-updater",
			Usage: "Set comment for each rule",
		},
		cli.BoolFlag{
			Name:  "dryrun",
			Usage: "Don't modify firewall rules",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:    "allow",
			Aliases: []string{"a"},
			Usage:   "Add allow rules",
			Action:  actionFor("allow"),
			Flags:   flags,
		},
		{
			Name:    "deny",
			Aliases: []string{"d"},
			Usage:   "Add deny rules",
			Action:  actionFor("deny"),
			Flags:   flags,
		},
	}

	app.Run(os.Args)
}

func actionFor(action string) func(*cli.Context) error {
	return func(c *cli.Context) error {
		appsId := c.String("apps-id")
		if appsId == "" {
			fmt.Fprintf(os.Stderr, "Apps ID not found\n")
			os.Exit(1)
			return nil
		}

		dryrun := c.Bool("dryrun")
		var dryrunPrefix string
		if dryrun {
			dryrunPrefix = "[DRYRUN] " // includes a space
		}

		// https://github.com/google/google-api-go-client#application-default-credentials-example
		ctx := context.Background()
		client, err := google.DefaultClient(ctx, appengine.AppengineAdminScope)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to google.DefaultClient because of %v\n", err)
			return err
		}

		service, err := appengine.New(client)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to appengine.New because of %v\n", err)
			return err
		}

		resp, err := service.Apps.Firewall.IngressRules.List(appsId).Do()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to service.Apps.Firewall.IngressRules.List(%q) because of %v\n", appsId, err)
			return err
		}

		base_priority := c.Int64("base-priority")
		max_priority := c.Int64("max-priority")

		usedPriorities := Int64Array{}
		oldRules := map[string]int64{}
		for _, rule := range resp.IngressRules {
			priority := rule.Priority
			usedPriorities = append(usedPriorities, priority)
			if base_priority <= priority && priority <= max_priority {
				oldRules[rule.SourceRange] = priority
			}
		}
		newSourceRanges := []string{}

		// https://golang.org/pkg/bufio/#Scanner
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			// fmt.Println(s.Text())
			newSoruceRange := s.Text()
			if newSoruceRange == "" {
				continue
			}
			_, ok := oldRules[newSoruceRange]
			if ok {
				delete(oldRules, newSoruceRange)
			} else {
				newSourceRanges = append(newSourceRanges, newSoruceRange)
			}
		}
		if err := s.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read from Stdin because of %v\n", err)
			return err
		}

		// The rest of oldRules are not found in given soruce ranges
		for _, priority := range oldRules {
			usedPriorities = usedPriorities.Remove(priority)
			fmt.Printf("%sDeleting rule of priority: %d\n", dryrunPrefix, priority)
			if !dryrun {
				if _, err := service.Apps.Firewall.IngressRules.Delete(appsId, fmt.Sprintf("%d", priority)).Do(); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to service.Apps.Firewall.IngressRules.Delete(%q, %d) because of %v\n", appsId, priority, err)
					return err
				}
			}
		}

		comment := c.String("comment")

		priority := base_priority
		for _, newSourceRange := range newSourceRanges {
			for usedPriorities.Include(priority) {
				priority += 1
			}
			usedPriorities = append(usedPriorities, priority)
			fmt.Printf("%sCreating rule %d %s %s %q\n", dryrunPrefix, priority, action, newSourceRange, comment)

			if !dryrun {
				newRule := &appengine.FirewallRule{
					Action:      action,
					Description: comment,
					Priority:    priority,
					SourceRange: newSourceRange,
				}
				if _, err := service.Apps.Firewall.IngressRules.Create(appsId, newRule).Do(); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to service.Apps.Firewall.IngressRules.Create(%q, %v) because of %v\n", appsId, newRule, err)
					return err
				}
			}
		}

		return nil
	}
}

type Int64Array []int64

func (c Int64Array) Include(value int64) bool {
	return (c.IndexOf(value) > -1)
}

func (c Int64Array) IndexOf(value int64) int {
	for i, val := range c {
		if val == value {
			return i
		}
	}
	return -1
}

func (c Int64Array) Remove(value int64) Int64Array {
	idx := c.IndexOf(value)
	if idx < 0 {
		return c
	}
	return append(c[:idx], c[idx+1:]...)
}
