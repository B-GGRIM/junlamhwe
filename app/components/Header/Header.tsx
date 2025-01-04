import Image from "next/image";
import Link from "next/link";

export default function Header() {
  return (
    <header className="w-full border-b border-gray-200">
      <div className="max-w-6xl mx-auto px-5 sm:px-7 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center gap-12">
          <Link href="/home" className="flex items-center gap-2">
            <Image
              src="/globe2.png"
              alt="로고"
              width={24}
              height={24}
              className="w-6 h-6"
              quality={100}
              priority
            />
            <h1 className="text-lg font-bold">이디저디</h1>
            <span className="px-2 py-1 text-xs bg-blue-500 text-white rounded-full">
              신규
            </span>
          </Link>
          <div className="flex items-center gap-8 ml-4">
            <Link 
              href="/special-rooms" 
              className="text-gray-600 hover:text-gray-900 font-bold text-lg"
            >
              특별실
            </Link>
            <Link 
              href="/electronics" 
              className="text-gray-600 hover:text-gray-900 font-bold text-lg"
            >
              전자기기
            </Link>
            <Link 
              href="/contact" 
              className="text-gray-600 hover:text-gray-900 font-bold text-lg"
            >
              문의하기
            </Link>
          </div>
        </div>
        
        <div className="flex items-center">
          <button className="p-2 hover:bg-gray-100 rounded-full">
            <Image
              src="/user.png"
              alt="사용자"
              width={26}
              height={26}
              quality={100}
            />
          </button>
        </div>
      </div>
    </header>
  );
};