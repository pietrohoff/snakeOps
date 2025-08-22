import sys
import importlib
import pkgutil

# Descobrir automaticamente comandos em snakeops.commands
def _discover_commands():
    import snakeops.commands as cmd_pkg
    commands = {}
    for mod in pkgutil.iter_modules(cmd_pkg.__path__):
        if mod.ispkg:
            continue
        name = mod.name
        module = importlib.import_module(f"snakeops.commands.{name}")
        cmd_name = getattr(module, "COMMAND_NAME", None) or name
        help_text = getattr(module, "COMMAND_HELP", "").strip()
        commands[cmd_name] = {
                "module": module,
                "help": help_text or "(sem descrição)",
        }
    return commands

def _print_global_help(commands):
    print("""\
snakeOps (sem dependências) — CLI unificada
Uso:
  python3 snakeOps <comando> [opções]

Comandos disponíveis:""")
    width = max(len(k) for k in commands) if commands else 0
    for name in sorted(commands):
        print(f"  {name.ljust(width)}  - {commands[name]['help']}")
    print("""\
Dicas:
  • Ajuda de um comando: python3 snakeOps <comando> -h
  • Exemplo: python3 snakeOps infoDns exemplo.com
""")

def main():
    commands = _discover_commands()

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        _print_global_help(commands)
        return

    cmd = sys.argv[1]
    if cmd not in commands:
        print(f"[ERRO] Comando desconhecido: {cmd}\n")
        _print_global_help(commands)
        sys.exit(1)

    module = commands[cmd]["module"]
    if hasattr(module, "run"):
        module.run(sys.argv[2:])
    else:
        print(f"[ERRO] Comando '{cmd}' não possui função run(args)." )
        sys.exit(1)
