from pucacon.cli import build_parser

def test_parser_defaults():
    p = build_parser()
    ns = p.parse_args(["targets.txt"])
    assert ns.targets_file == "targets.txt"
    assert ns.passive is False
    assert ns.output  # has a default

def test_parser_flags():
    ns = build_parser().parse_args(["t.txt", "-o", "run1", "--passive", "--brute"])
    assert ns.output == "run1" and ns.passive is True and ns.brute is True
