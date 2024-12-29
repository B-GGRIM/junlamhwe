export default function Footer() {
  return (
    <footer className="bg-gray-100 mt-auto">
      <div className="max-w-7xl mx-auto py-6 px-4">
        <div className="flex flex-col items-center justify-center">
          <p className="text-gray-600 text-sm">© 2025 Bunker. All rights reserved.</p>
          <div className="mt-2 text-gray-500 text-xs">
            <a href="/privacy" className="hover:text-gray-700 mx-2">개인정보처리방침</a>
            <span>|</span>
            <a href="/terms" className="hover:text-gray-700 mx-2">이용약관</a>
          </div>
        </div>
      </div>
    </footer>
  )
}