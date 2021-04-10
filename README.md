# hashcheck
Check if a list of hashes exist in another list of hashes.

# Who?
* [@bridgeythegeek](https://twitter.com/bridgeythegeek)
* https://github.com/bridgeythegeek

# What?
A POSIX C multithreaded application to check a list of hashes to see if any are present in another list of hashes.

* Supports MD5 and SHA1.

# Where?
* https://github.com/bridgeythegeek/hashcheck

# Why?
* Originally written to provide a fast way to check if any of a list of hashes are present in the [NSRL hash set](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/current-rds).
* But the haystack doesn't have to be the NSRL hash set.

# How?
```
$ hashcheck my_hashes.txt --sha1|--md5
```
