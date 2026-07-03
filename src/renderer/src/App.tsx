function App() {
  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_#fff9ef,_#f5efe2_48%,_#e6dcc8)] text-stone-900">
      <section className="mx-auto flex min-h-screen w-full max-w-6xl flex-col justify-between px-6 py-8 md:px-10 md:py-12">
        <header className="flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.35em] text-amber-700">
              Initial Sketch
            </p>
            <h1 className="font-display text-4xl leading-none md:text-6xl">
              Easybrowser
            </h1>
          </div>
          <div className="rounded-full border border-stone-900/10 bg-white/70 px-4 py-2 text-sm shadow-sm backdrop-blur">
            Built with Electron + React
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="rounded-[2rem] border border-stone-900/10 bg-white/75 p-6 shadow-[0_24px_80px_rgba(74,58,31,0.10)] backdrop-blur md:p-8">
            <div className="mb-6 flex items-center gap-3">
              <div className="h-3 w-3 rounded-full bg-rose-400" />
              <div className="h-3 w-3 rounded-full bg-amber-400" />
              <div className="h-3 w-3 rounded-full bg-emerald-400" />
            </div>

            <div className="space-y-5">
              <div className="rounded-2xl bg-stone-950 px-5 py-4 text-sm text-stone-100 shadow-inner">
                Search or open a trusted page with one clear action.
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <article className="rounded-2xl bg-amber-100/80 p-5">
                  <p className="mb-2 text-sm font-medium text-amber-900">
                    Calm UI
                  </p>
                  <p className="text-sm text-stone-700">
                    Large targets, low-noise layout, and space for guided
                    browsing flows.
                  </p>
                </article>

                <article className="rounded-2xl bg-emerald-100/80 p-5">
                  <p className="mb-2 text-sm font-medium text-emerald-900">
                    Safe defaults
                  </p>
                  <p className="text-sm text-stone-700">
                    Electron shell is ready for a preload bridge and isolated
                    renderer.
                  </p>
                </article>
              </div>
            </div>
          </div>

          <aside className="space-y-4 rounded-[2rem] border border-stone-900/10 bg-stone-950 p-6 text-stone-50 shadow-[0_24px_80px_rgba(20,20,20,0.18)] md:p-8">
            <p className="text-xs uppercase tracking-[0.3em] text-amber-300/80">
              Foundation
            </p>
            <h2 className="font-display text-3xl leading-tight">
              Renderer, preload, and main process are wired together.
            </h2>
            <p className="text-sm leading-6 text-stone-300">
              This scaffold gives us a clean starting point for browser chrome,
              tabs, navigation, and trusted-site flows without backtracking on
              tooling.
            </p>

            <div className="grid gap-3">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <p className="text-sm text-stone-200">React + TypeScript renderer</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <p className="text-sm text-stone-200">Electron main + preload bridge</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <p className="text-sm text-stone-200">Tailwind styling pipeline</p>
              </div>
            </div>
          </aside>
        </section>
      </section>
    </main>
  )
}

export default App
