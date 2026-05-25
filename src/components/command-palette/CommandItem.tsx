interface Props {
  label: string
  description: string
  shortcut?: string
  isSelected: boolean
  onClick: () => void
}

export default function CommandItem({ label, description, shortcut, isSelected, onClick }: Props) {
  return (
    <div
      onClick={onClick}
      className={[
        'flex items-center justify-between px-4 py-2.5 cursor-pointer transition-colors duration-75',
        'border-l-2',
        isSelected
          ? 'bg-neon/10 border-neon text-neon'
          : 'border-transparent text-neon/60 hover:bg-neon/5 hover:text-neon/80',
      ].join(' ')}
    >
      <div className="flex flex-col gap-0.5">
        <span className="text-xs tracking-wider">{label}</span>
        <span className="text-[10px] text-neon/35 tracking-wide">{description}</span>
      </div>
      {shortcut && (
        <span className="text-[10px] tracking-widest text-neon/30 border border-neon/20 px-1.5 py-0.5 ml-4 shrink-0">
          {shortcut}
        </span>
      )}
    </div>
  )
}
