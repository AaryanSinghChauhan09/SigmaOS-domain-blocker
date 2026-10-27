    # SigmaOS-domain-blocker

    Block domains system-wide via /etc/hosts

    Part of the **SigmaOS** sovereign operating-system ecosystem — a multi-repository
    distribution modelled on Linux Mint and Omarchy Linux. See the parent
    [`SigmaOS`](https://github.com/AaryanSinghChauhan09/SigmaOS) repository for the
    full component index.

    ## Upstream inspirations
    - https://github.com/linuxmint/mintnanny

    ## Design principles applied
    - **Separation of Mechanism & Policy**
- **Defensive Programming**
- **Fail-Fast**
- **KISS**
- **Information Hiding**

    ## Usage
    Verbs: `add, remove, list, enable, disable, status`

    ```
    $ sigma-block add ads.example.com tracker.example.net
$ sigma-block list
$ sigma-block enable          # merge managed block into /etc/hosts
$ sigma-block status

    ```

    ## Build & test
    ```
    make build
    make test
    ```

    ## Licence
    GNU General Public License v3.0 (FOSS).
