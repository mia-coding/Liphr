import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base must match your repo name so assets load at mia-coding.github.io/Liphr/
export default defineConfig({
  plugins: [react()],
  base: '/Liphr/',
})
