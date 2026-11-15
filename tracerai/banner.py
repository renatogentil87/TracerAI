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
   {c}   │       │                           {b}███████║██║{r}   {d}Troubleshooting Agent{r}
   {c}   ●───────●───────●                   {b}██╔══██║██║{r}
   {c}                   │                   {b}██║  ██║██║{r}
   {c}                   ●                   {b}╚═╝  ╚═╝╚═╝{r}
"""

WELCOME = (
    "{b}Welcome to TracerAI.{r}\n"
    "Tell me how you'd like to troubleshoot your network and I'll review it for you.\n"
    "{d}e.g. \"can the web server reach the database on 3306?\"   (type 'quit' to exit){r}"
)


def print_banner():
    print(BANNER.format(c=CYAN, b=BOLD + CYAN, d=DIM, r=RESET))
    print(WELCOME.format(b=BOLD, d=DIM, r=RESET))
