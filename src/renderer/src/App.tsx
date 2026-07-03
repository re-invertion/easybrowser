function App() {
  return (
    <main className="min-h-screen bg-app text-app-text">
      <section className="mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center px-5 py-8">
        <div className="w-full max-w-3xl">
          <div className="mb-6 text-center">
            <h1 className="text-3xl leading-tight font-bold md:text-5xl">
              Wyszukaj w internecie
            </h1>
          </div>

          <form className="rounded-full border border-app-tile-border bg-app-tile px-5 py-3 shadow-[0_14px_40px_rgba(148,163,184,0.18)]">
            <label className="sr-only" htmlFor="search">
              Wyszukaj w Google
            </label>
            <div className="flex items-center gap-3">
              <div
                aria-label="Google"
                className="font-google shrink-0 text-2xl leading-none tracking-tight md:text-3xl"
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
                placeholder="Wpisz, czego szukasz"
                className="focus-ring w-full rounded-full bg-transparent px-4 py-3 text-lg text-app-text placeholder:text-slate-400 focus:outline-none md:text-xl"
              />
            </div>
          </form>
        </div>
      </section>
    </main>
  )
}

export default App
