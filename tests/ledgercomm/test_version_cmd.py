def test_version(cmd):
    assert cmd.get_version() == (2, 1, 0)
