"""Startup banner for TracerAI."""

CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER = r"""
   {c}●───────────●                                                     {r}
   {c}│           │        {b}████████╗██████╗  █████╗  ██████╗███████╗██████╗ {r}
   {c}●─────●─────●        {b}╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗{r}
   {c}      │     │           {b}██║   ██████╔╝███████║██║     █████╗  ██████╔╝{r}
   {c}      ●─────●───●       {b}██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗{r}
   {c}            │              {b}██║   ██║  ██║██║  ██║╚██████╗███████╗██║  ██║{r}
   {c}            ●              {b}╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝{r}
   {c}                                        {b}█████╗ ██╗{r}
   {c}   ●───────●                           {b}██╔══██╗██║{r}   {d}AWS Network{r}
   {c}   │       │                           {b}███████║██║{r}   {d}Agent{r}
   {c}   ●───────●───────●                   {b}██╔══██║██║{r}
   {c}                   │                   {b}██║  ██║██║{r}
   {c}                   ●                   {b}╚═╝  ╚═╝╚═╝{r}
"""

WELCOME = (
    "{b}Welcome to TracerAI.{r}\n"
    "I'm your AWS Networking Agent.\n"
    "{d}e.g. \"can the web server reach the database on 3306?\"\n"
    "e.g. \"can you discover my network in ca-central-1?\"\n"
    "(type 'quit' to exit){r}"
)


def print_banner():
    print(BANNER.format(c=CYAN, b=BOLD + CYAN, d=DIM, r=RESET))
    print(WELCOME.format(b=BOLD, d=DIM, r=RESET))
