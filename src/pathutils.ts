function unix_absolute(path: string) {
  const re = /^\/[^\\/](?!\.{1,2}($|\/))((?!\/[./](\/|$))\/?.)*\/?(?<!\/\.{1,1})$/i

  return re.test(path)
}

function unix_relative(path: string) {
  const re = /^.{1,2}\/(?:.{2}|\w)*$/i
  return re.test(path)
}

function win_absolute(path: string) {
  const re = /^(?:(?:[a-z]:\\)|\\)(((?![<>:"/\\|?*]).)+(?:(?<![ .])\\)?)*$/i
  return re.test(path)
}

function unix_valid(path: string) {
  return unix_absolute(path) || unix_relative(path)
}

function win_relative(path: string) {
  const re =
    /^(?:(?:[a-z]:)|[a-z0-9]|\.{2}\\)(?:(?:(?:(?![<>:"/\\|?*]).)|(?:\.{2}))+(?:(?<![ .]{3})\\)?)*$/i
  return re.test(path)
}

function win_valid(path: string) {
  return win_absolute(path) || win_relative(path)
}

export function isPath(path: string) {
  return win_valid(path) || unix_valid(path)
}

export function isAbsolute(path: string) {
  return win_absolute(path) || unix_absolute(path)
}

export function relative(path: string) {
  return win_relative(path) || unix_relative(path)
}

export function absolute(path: string) {
  return win_absolute(path) || unix_absolute(path)
}

export function win(path: string) {
  return win_valid(path)
}

export function unix(path: string) {
  return unix_valid(path)
}
