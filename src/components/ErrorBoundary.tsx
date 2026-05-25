import { Component, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  label?: string
}

interface State {
  error: Error | null
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error(`[ErrorBoundary${this.props.label ? ':' + this.props.label : ''}]`, error, info.componentStack)
  }

  render() {
    const { error } = this.state
    if (error) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-3 p-4 select-none">
          <span className="text-alert text-xs tracking-[0.4em]">▲ PANEL ERROR</span>
          {this.props.label && (
            <span className="text-alert/40 text-[10px] tracking-widest">{this.props.label}</span>
          )}
          <span className="text-alert/50 text-[10px] text-center max-w-[240px] break-all font-mono leading-relaxed">
            {error.message}
          </span>
          <button
            onClick={() => this.setState({ error: null })}
            className="text-[10px] tracking-widest px-3 py-1 border border-alert/40 text-alert/60 hover:border-alert hover:text-alert transition-colors duration-150"
          >
            ↺ RETRY
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
