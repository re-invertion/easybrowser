import { FormEvent, useEffect, useRef, useState } from 'react'
import { FiAlertTriangle, FiMoreVertical, FiTrash2, FiX } from 'react-icons/fi'

type ViewMode = 'home' | 'browser'

const GOOGLE_HOME_URL = 'https://www.google.pl/?hl=pl&gl=PL&pws=0'

function normalizeAddress(value: string): string {
  const trimmed = value.trim()

  if (trimmed.length === 0) {
    return GOOGLE_HOME_URL
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }

  if (/^[^\s]+\.[^\s]+$/.test(trimmed)) {
    return `https://${trimmed}`
  }

  return `https://www.google.pl/search?hl=pl&gl=PL&pws=0&q=${encodeURIComponent(trimmed)}`
}

function WindowControls({
  isMaximized,
  onMinimize,
  onToggleMaximize,
  onClose
}: {
  isMaximized: boolean
  onMinimize: () => void
  onToggleMaximize: () => void
  onClose: () => void
}) {
  return (
    <div className="app-no-drag flex items-center gap-2">
      <button
        aria-label="Minimalizuj okno"
        className="window-control-button"
        type="button"
        onClick={onMinimize}
      >
        <span className="window-control-line" />
      </button>

      <button
        aria-label={isMaximized ? 'Przywróć rozmiar okna' : 'Maksymalizuj okno'}
        className="window-control-button"
        type="button"
        onClick={onToggleMaximize}
      >
        {isMaximized ? (
          <svg
            aria-hidden="true"
            className="h-3.5 w-3.5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <rect x="7" y="7" width="10" height="10" rx="1" />
            <path d="M10 7V5h9v9h-2" />
          </svg>
        ) : (
          <svg
            aria-hidden="true"
            className="h-3.5 w-3.5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <rect x="5" y="5" width="14" height="14" rx="1" />
          </svg>
        )}
      </button>

      <button
        aria-label="Zamknij okno"
        className="window-control-button window-control-button-close"
        type="button"
        onClick={onClose}
      >
        <svg
          aria-hidden="true"
          className="h-3.5 w-3.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <path d="m6 6 12 12" />
          <path d="M18 6 6 18" />
        </svg>
      </button>
    </div>
  )
}

function App() {
  const browserChromeRef = useRef<HTMLElement | null>(null)
  const [mode, setMode] = useState<ViewMode>('home')
  const [users, setUsers] = useState<UserProfile[]>([])
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)
  const [isLoadingUsers, setIsLoadingUsers] = useState(true)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [inputValue, setInputValue] = useState('')
  const [currentUrl, setCurrentUrl] = useState(GOOGLE_HOME_URL)
  const [pageTitle, setPageTitle] = useState('Easybrowser')
  const [isLoading, setIsLoading] = useState(false)
  const [canGoBack, setCanGoBack] = useState(false)
  const [canGoForward, setCanGoForward] = useState(false)
  const [isMaximized, setIsMaximized] = useState(false)
  const [copyNoticeVisible, setCopyNoticeVisible] = useState(false)
  const [isAddingUser, setIsAddingUser] = useState(false)
  const [newUserName, setNewUserName] = useState('')
  const [openUserMenuId, setOpenUserMenuId] = useState<string | null>(null)
  const [userPendingDeletion, setUserPendingDeletion] = useState<UserProfile | null>(null)

  const selectedUser = users.find((user) => user.id === selectedUserId) ?? null

  useEffect(() => {
    const loadUsers = async () => {
      try {
        const state = await window.easybrowser.getUserState()
        setUsers(state.users)
        setSelectedUserId(state.activeUserId)
      } catch (error) {
        setErrorMessage(
          error instanceof Error ? error.message : 'Nie udało się wczytać użytkowników.'
        )
      } finally {
        setIsLoadingUsers(false)
      }
    }

    const unsubscribe = window.easybrowser.onBrowserStateChange((state: BrowserState) => {
      setMode(state.mode)
      setCurrentUrl(state.url || GOOGLE_HOME_URL)
      setInputValue(state.url || '')
      setPageTitle(state.title || 'Easybrowser')
      setIsLoading(state.isLoading)
      setCanGoBack(state.canGoBack)
      setCanGoForward(state.canGoForward)
      setIsMaximized(state.isMaximized)
      setErrorMessage(state.error)
    })

    void loadUsers()

    return unsubscribe
  }, [])

  useEffect(() => {
    if (mode !== 'browser') {
      return
    }

    const element = browserChromeRef.current

    if (!element) {
      return
    }

    const updateHeight = () => {
      void window.easybrowser.setBrowserChromeHeight(element.offsetHeight)
    }

    updateHeight()

    const observer = new ResizeObserver(() => {
      updateHeight()
    })

    observer.observe(element)
    window.addEventListener('resize', updateHeight)

    return () => {
      observer.disconnect()
      window.removeEventListener('resize', updateHeight)
    }
  }, [mode, canGoBack, canGoForward, inputValue, isMaximized])

  useEffect(() => {
    if (!openUserMenuId) {
      return
    }

    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target

      if (!(target instanceof HTMLElement)) {
        return
      }

      if (target.closest(`[data-user-menu-root="${openUserMenuId}"]`)) {
        return
      }

      setOpenUserMenuId(null)
    }

    window.addEventListener('pointerdown', handlePointerDown)

    return () => {
      window.removeEventListener('pointerdown', handlePointerDown)
    }
  }, [openUserMenuId])

  const applyUserState = (state: UserState) => {
    setUsers(state.users)
    setSelectedUserId(state.activeUserId)
    setErrorMessage(null)
  }

  const openInBrowser = async (rawValue: string) => {
    const destination = normalizeAddress(rawValue)
    setInputValue(destination)
    setCurrentUrl(destination)
    setIsLoading(true)
    await window.easybrowser.navigate(destination)
  }

  const handleSearchSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    await openInBrowser(inputValue)
  }

  const handleSelectUser = async (userId: string) => {
    try {
      const state = await window.easybrowser.selectUser(userId)
      applyUserState(state)
      setIsAddingUser(false)
      setNewUserName('')
      setInputValue('')
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się wybrać użytkownika.'
      )
    }
  }

  const handleClearActiveUser = async () => {
    try {
      const state = await window.easybrowser.clearActiveUser()
      applyUserState(state)
      setIsAddingUser(false)
      setNewUserName('')
      setInputValue('')
      setCurrentUrl(GOOGLE_HOME_URL)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zmienić użytkownika.'
      )
    }
  }

  const handleAddUser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    try {
      const state = await window.easybrowser.createUser(newUserName)
      applyUserState(state)
      setIsAddingUser(false)
      setNewUserName('')
      setInputValue('')
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się dodać użytkownika.'
      )
    }
  }

  const handleDeleteUser = async (userId: string) => {
    try {
      const state = await window.easybrowser.deleteUser(userId)
      applyUserState(state)
      setOpenUserMenuId(null)
      setUserPendingDeletion(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się usunąć użytkownika.'
      )
    }
  }

  const goHome = async () => {
    await window.easybrowser.goHome()
    setInputValue('')
    setCurrentUrl(GOOGLE_HOME_URL)
    setPageTitle('Easybrowser')
    setIsLoading(false)
    setCanGoBack(false)
    setCanGoForward(false)
  }

  const navigateBack = () => {
    void window.easybrowser.goBack()
  }

  const navigateForward = () => {
    void window.easybrowser.goForward()
  }

  const reloadPage = () => {
    void window.easybrowser.reload()
  }

  const toggleMaximize = () => {
    void window.easybrowser.toggleMaximize()
  }

  const copyCurrentUrl = () => {
    void window.easybrowser.copyText(currentUrl)
    setCopyNoticeVisible(true)
    window.setTimeout(() => {
      setCopyNoticeVisible(false)
    }, 1600)
  }

  const minimizeWindow = () => {
    void window.easybrowser.minimizeWindow()
  }

  const closeWindow = () => {
    void window.easybrowser.closeWindow()
  }

  const closeDeleteModal = () => {
    setUserPendingDeletion(null)
  }

  if (isLoadingUsers) {
    return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
        <div className="app-shell flex h-full w-full items-center justify-center">
          <h1 className="text-2xl font-bold md:text-3xl">Ładowanie użytkowników...</h1>
        </div>
      </main>
    )
  }

  if (mode === 'browser') {
    return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
        <div className="app-shell flex h-full w-full flex-col overflow-hidden border-0 shadow-none">
          <header
            ref={(node) => {
              browserChromeRef.current = node
            }}
            className="border-b border-app-tile-border bg-app-tile shadow-[0_10px_30px_rgba(148,163,184,0.12)]"
          >
            <div className="flex h-12 items-center justify-between border-b border-app-tile-border px-4">
              <div className="app-drag-region min-w-0 flex flex-1 items-center gap-3 pr-4 select-none">
                <p className="truncate text-sm font-bold text-app-text">
                  Przegladarka
                </p>
                <div className="app-drag-surface flex h-8 flex-1 items-center justify-center rounded-full border border-dashed border-slate-200 bg-slate-50/70 px-3">
                  <span className="app-drag-label text-xs font-medium text-slate-400">
                    Przeciągnij okno
                  </span>
                </div>
              </div>

              <WindowControls
                isMaximized={isMaximized}
                onMinimize={minimizeWindow}
                onToggleMaximize={toggleMaximize}
                onClose={closeWindow}
              />
            </div>

            <div className="mx-auto flex w-full max-w-7xl flex-col gap-3 px-4 py-4">
              <div className="flex flex-wrap items-center gap-3">
                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-app-tile px-4 py-3 text-sm font-bold text-app-text disabled:cursor-not-allowed disabled:opacity-40"
                  type="button"
                  onClick={navigateBack}
                  disabled={!canGoBack}
                >
                  Wstecz
                </button>

                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-app-tile px-4 py-3 text-sm font-bold text-app-text disabled:cursor-not-allowed disabled:opacity-40"
                  type="button"
                  onClick={navigateForward}
                  disabled={!canGoForward}
                >
                  Dalej
                </button>

                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-app-tile px-4 py-3 text-sm font-bold text-app-text"
                  type="button"
                  onClick={reloadPage}
                >
                  Odśwież
                </button>

                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-slate-50 px-4 py-3 text-sm font-bold text-app-text hover:bg-slate-100"
                  type="button"
                  onClick={goHome}
                >
                  Strona główna
                </button>

                <form
                  className="min-w-[320px] flex-1 rounded-full border border-app-tile-border bg-app-tile px-4 py-2"
                  onSubmit={handleSearchSubmit}
                >
                  <label className="sr-only" htmlFor="browser-address">
                    Adres strony lub wyszukiwanie
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id="browser-address"
                      type="text"
                      value={inputValue}
                      onChange={(event) => setInputValue(event.target.value)}
                      className="focus-ring w-full rounded-full bg-transparent px-3 py-2 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                      placeholder="Wpisz adres strony lub wyszukaj"
                    />

                    <div className="relative flex shrink-0 items-center">
                      <button
                        aria-label="Kopiuj adres strony"
                      className="focus-ring flex h-9 w-9 items-center justify-center rounded-full text-slate-500 transition-colors hover:bg-slate-100 hover:text-app-text"
                        type="button"
                        onClick={copyCurrentUrl}
                      >
                        <svg
                          aria-hidden="true"
                          className="h-4 w-4"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                        >
                          <rect x="9" y="9" width="10" height="10" rx="1" />
                          <rect x="5" y="5" width="10" height="10" rx="1" />
                        </svg>
                      </button>

                      {copyNoticeVisible ? (
                        <div className="pointer-events-none absolute bottom-[calc(100%+0.4rem)] right-0 z-[9999] whitespace-nowrap rounded-xl bg-slate-900 px-3 py-2 text-xs font-medium text-white shadow-lg">
                          Skopiowano do schowka
                        </div>
                      ) : null}
                    </div>
                  </div>
                </form>
              </div>
            </div>
          </header>

          <section className="min-h-0 flex-1 overflow-hidden bg-white" />
        </div>
      </main>
    )
  }

  if (selectedUser) {
    return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
        <div className="app-shell flex h-full w-full flex-col overflow-hidden border-0 shadow-none">
          <header className="border-b border-app-tile-border bg-app-tile shadow-[0_10px_30px_rgba(148,163,184,0.12)]">
            <div className="flex h-12 items-center justify-between px-4">
              <div className="app-drag-region min-w-0 flex flex-1 items-center gap-3 pr-4 select-none">
                <p className="truncate text-sm font-bold text-app-text">
                  Przegladarka
                </p>
                <div className="app-drag-surface flex h-8 flex-1 items-center justify-center rounded-full border border-dashed border-slate-200 bg-slate-50/70 px-3">
                  <span className="app-drag-label text-xs font-medium text-slate-400">
                    Przeciągnij okno
                  </span>
                </div>
              </div>

              <WindowControls
                isMaximized={isMaximized}
                onMinimize={minimizeWindow}
                onToggleMaximize={toggleMaximize}
                onClose={closeWindow}
              />
            </div>
          </header>

          <section className="mx-auto flex min-h-0 flex-1 w-full max-w-5xl items-center justify-center overflow-hidden px-4 py-6 sm:px-5 sm:py-8">
            <div className="mx-auto w-full max-w-2xl md:max-w-3xl">
              <div className="mb-10 text-center">
                <p className="mb-3 text-sm font-bold tracking-[0.16em] text-slate-500 uppercase">
                  Użytkownik
                </p>
                <h1 className="text-3xl leading-tight font-bold md:text-5xl">
                  Witaj, {selectedUser.name}
                </h1>
                <p className="mt-3 text-base text-slate-500 md:text-lg">
                  Możesz już wyszukać coś w internecie.
                </p>
              </div>

              <form
                className="overflow-hidden rounded-full border border-app-tile-border bg-app-tile px-4 py-2.5 shadow-[0_14px_40px_rgba(148,163,184,0.18)] sm:px-5 sm:py-3"
                onSubmit={handleSearchSubmit}
              >
                <div className="flex items-center gap-2 sm:gap-3">
                  <div
                    aria-label="Google"
                    className="font-google shrink-0 text-xl leading-none tracking-tight sm:text-2xl md:text-3xl"
                  >
                    <span className="text-[#4285F4]">G</span>
                    <span className="text-[#EA4335]">o</span>
                    <span className="text-[#FBBC05]">o</span>
                    <span className="text-[#4285F4]">g</span>
                    <span className="text-[#34A853]">l</span>
                    <span className="text-[#EA4335]">e</span>
                  </div>

                  <div className="h-7 w-px bg-slate-200" />

                  <input
                    id="search"
                    type="text"
                    value={inputValue}
                    onChange={(event) => setInputValue(event.target.value)}
                    placeholder="Wpisz, czego szukasz"
                  className="focus-ring min-w-0 w-full rounded-full bg-transparent px-3 py-2 text-base text-app-text placeholder:text-slate-400 focus:outline-none sm:px-4 sm:py-3 sm:text-lg md:text-xl"
                  />
                </div>
              </form>

              <div className="mt-8 text-center">
                <button
                  type="button"
                  className="focus-ring rounded-full px-4 py-2 text-sm font-bold text-app-primary transition hover:bg-slate-100"
                  onClick={() => {
                    void handleClearActiveUser()
                  }}
                >
                  Zmień użytkownika
                </button>
              </div>
            </div>
          </section>
        </div>
      </main>
    )
  }

  return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
      <div className="app-shell relative flex h-full w-full flex-col overflow-hidden border-0 shadow-none">
        <header className="border-b border-app-tile-border bg-app-tile shadow-[0_10px_30px_rgba(148,163,184,0.12)]">
          <div className="flex h-12 items-center justify-between px-4">
            <div className="app-drag-region min-w-0 flex flex-1 items-center gap-3 pr-4 select-none">
              <p className="truncate text-sm font-bold text-app-text">
                Przegladarka
              </p>
              <div className="app-drag-surface flex h-8 flex-1 items-center justify-center rounded-full border border-dashed border-slate-200 bg-slate-50/70 px-3">
                <span className="app-drag-label text-xs font-medium text-slate-400">
                  Przeciągnij okno
                </span>
              </div>
            </div>

            <WindowControls
              isMaximized={isMaximized}
              onMinimize={minimizeWindow}
              onToggleMaximize={toggleMaximize}
              onClose={closeWindow}
            />
          </div>
        </header>

        <section className="mx-auto flex min-h-0 flex-1 w-full max-w-5xl items-center justify-center overflow-hidden px-4 py-6 sm:px-5 sm:py-8">
          <div className="w-full max-w-3xl">
            <div className="mb-10 text-center">
              <h1 className="text-3xl leading-tight font-bold md:text-5xl">
                Kto korzysta z internetu?
              </h1>
              <p className="mt-3 text-base text-slate-500 md:text-lg">
                Wybierz użytkownika
              </p>
            </div>

            {errorMessage ? (
              <div className="mb-6 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                {errorMessage}
              </div>
            ) : null}

            {users.length > 0 ? (
              <div className="flex flex-wrap justify-center gap-4">
                {users.map((user) => (
                  <button
                    key={user.id}
                    type="button"
                    className="focus-ring relative w-full max-w-[244px] rounded-[24px] border border-app-tile-border bg-app-tile p-5 text-left shadow-[0_14px_34px_rgba(148,163,184,0.12)] transition hover:-translate-y-0.5 hover:shadow-[0_18px_40px_rgba(148,163,184,0.16)] sm:w-[244px]"
                    onClick={() => {
                      void handleSelectUser(user.id)
                    }}
                  >
                    <div className="absolute top-3 right-3" data-user-menu-root={user.id}>
                      <button
                        type="button"
                        aria-label={`Opcje użytkownika ${user.name}`}
                        className="focus-ring flex h-8 w-8 items-center justify-center rounded-full text-slate-500 transition-colors hover:bg-slate-100 hover:text-app-text"
                        onClick={(event) => {
                          event.stopPropagation()
                          setOpenUserMenuId((currentId) =>
                            currentId === user.id ? null : user.id
                          )
                        }}
                      >
                        <FiMoreVertical aria-hidden="true" className="h-4 w-4" />
                      </button>

                      {openUserMenuId === user.id ? (
                        <div className="absolute top-[calc(100%+0.35rem)] right-0 z-20 min-w-[172px] rounded-2xl border border-app-tile-border bg-app-tile p-2 shadow-[0_18px_40px_rgba(148,163,184,0.18)]">
                          <button
                            type="button"
                            className="focus-ring flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-sm font-medium text-red-600 transition hover:bg-red-50"
                            onClick={(event) => {
                              event.stopPropagation()
                              setOpenUserMenuId(null)
                              setUserPendingDeletion(user)
                            }}
                          >
                            <FiTrash2 aria-hidden="true" className="h-4 w-4 shrink-0" />
                            Usuń użytkownika
                          </button>
                        </div>
                      ) : null}
                    </div>

                    <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-lg font-bold text-app-text">
                      {user.initials}
                    </div>
                    <h2 className="mt-4 text-xl font-bold text-app-text">{user.name}</h2>
                    <p className="mt-1 text-sm text-slate-500">
                      Kliknij, aby wybrać użytkownika
                    </p>
                  </button>
                ))}
              </div>
            ) : (
              <div className="rounded-[24px] border border-dashed border-app-tile-border bg-app-tile/70 px-6 py-10 text-center text-slate-500">
                Nie ma jeszcze żadnego użytkownika
              </div>
            )}

            {isAddingUser ? (
              <form
                className="mt-8 rounded-[24px] border border-app-tile-border bg-app-tile p-5 shadow-[0_14px_34px_rgba(148,163,184,0.12)]"
                onSubmit={(event) => {
                  void handleAddUser(event)
                }}
              >
                <label
                  className="mb-4 block text-sm font-bold text-app-text"
                  htmlFor="new-user-name"
                >
                  Nazwa użytkownika
                </label>
                <input
                  id="new-user-name"
                  type="text"
                  value={newUserName}
                  onChange={(event) => setNewUserName(event.target.value)}
                  placeholder="Wpisz imię użytkownika"
                  className="focus-ring w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                  autoFocus
                />

                <div className="mt-6 flex flex-wrap items-center gap-3">
                  <button
                    type="submit"
                    className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text"
                  >
                    Dodaj użytkownika
                  </button>
                  <button
                    type="button"
                    className="focus-ring rounded-full border border-app-tile-border px-5 py-3 text-sm font-bold text-app-text"
                    onClick={() => {
                      setIsAddingUser(false)
                      setNewUserName('')
                    }}
                  >
                    Anuluj
                  </button>
                </div>
              </form>
            ) : (
              <div className="mt-8 text-center">
                <button
                  type="button"
                  className="focus-ring rounded-full border border-app-primary/18 bg-app-tile px-5 py-3 text-sm font-bold text-app-primary shadow-[0_10px_24px_rgba(148,163,184,0.12)] transition hover:-translate-y-0.5 hover:bg-slate-50 hover:shadow-[0_14px_28px_rgba(148,163,184,0.16)]"
                  onClick={() => {
                    setIsAddingUser(true)
                    setErrorMessage(null)
                  }}
                >
                  Nie ma Cię tu? Dodaj nowego użytkownika
                </button>
              </div>
            )}
          </div>
        </section>

        {userPendingDeletion ? (
          <div
            className="absolute inset-0 z-[200] flex items-center justify-center bg-slate-950/30 px-4 backdrop-blur-[2px]"
            onClick={closeDeleteModal}
          >
            <div
              className="w-full max-w-md rounded-[28px] border border-red-200 bg-white p-6 shadow-[0_28px_80px_rgba(15,23,42,0.24)]"
              onClick={(event) => {
                event.stopPropagation()
              }}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-4">
                  <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-red-50 text-red-600">
                    <FiAlertTriangle aria-hidden="true" className="h-6 w-6" />
                  </div>

                  <div>
                    <h2 className="text-xl font-bold text-app-text">
                      Czy na pewno chcesz usunąć użytkownika?
                    </h2>
                    <p className="mt-2 text-sm leading-6 text-slate-500">
                      Użytkownik <span className="font-bold text-app-text">{userPendingDeletion.name}</span>{' '}
                      zostanie usunięty razem z jego danymi przeglądania.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  aria-label="Zamknij okno potwierdzenia"
                  className="focus-ring flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-slate-400 transition hover:bg-slate-100 hover:text-app-text"
                  onClick={closeDeleteModal}
                >
                  <FiX aria-hidden="true" className="h-5 w-5" />
                </button>
              </div>

              <div className="mt-6 flex flex-wrap justify-end gap-3">
                <button
                  type="button"
                  className="focus-ring rounded-full border border-app-tile-border px-5 py-3 text-sm font-bold text-app-text"
                  onClick={closeDeleteModal}
                >
                  Anuluj
                </button>
                <button
                  type="button"
                  className="focus-ring rounded-full bg-red-600 px-5 py-3 text-sm font-bold text-white transition hover:bg-red-700"
                  onClick={() => {
                    void handleDeleteUser(userPendingDeletion.id)
                  }}
                >
                  Usuń użytkownika
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </main>
  )
}

export default App
