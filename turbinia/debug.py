from os import getenv


def initialize_debugmode_if_requested():
  if getenv('TURBINIA_DEBUG') == "1":
    import debugpy
    debug_port = getenv('TURBINIA_DEBUG_PORT')
    debugpy.listen(("0.0.0.0", int(debug_port)))
    print('Debugger can now be attached on port {0:s}'.format(debug_port))
  if getenv('TURBINIA_HOTRELOAD') == "1":
    import jurigged
    jurigged.watch('turbinia/')
    print('Code hot reloading enabled.')
