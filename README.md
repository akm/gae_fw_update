# GAE FW Update

## Install

```
$ go get github.com/akm/gae_fw_update
```

## Usage

```
$ cat source_ranges.txt | gae_fw_update allow --apps-id=<YOUR_GCP_PROJECT> --comment="For App Engine"
```

### Clear

```
$ echo "" | gae_fw_update allow --apps-id=<YOUR_GCP_PROJECT> --comment="For App Engine"
```

### source_ranges.txt

A text file including source_ranges like this:

```
35.190.224.0/20
35.232.0.0/15
35.234.0.0/16
35.235.0.0/17
35.235.192.0/20
```
