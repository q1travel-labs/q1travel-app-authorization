declare module '*?raw' {
  const source: string
  export default source
}

interface ImportMeta {
  glob<T = unknown>(
    pattern: string,
    options: { query: string; import: string; eager: true },
  ): Record<string, T>
}
