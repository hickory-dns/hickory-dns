# Fuzzing

There are some basic fuzzing configurations in `fuzz_targets`. These can be run simply with:

```shell
&> cargo fuzz run message --sanitizer=none -- -max_len=1500 -use_value_profile=1
```

Ideally this should run for an indefinite period of time before finding an issue.
