import Image from "next/image";
import Link from "next/link";

const PreHeader = () => {
  return (
    <header className="w-full border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
        <div className="flex items-center">
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
        </div>
        
        <div className="flex items-center gap-4">
          <Link 
            href="/contact" 
            className="text-gray-600 hover:text-gray-900"
          >
            문의하기
          </Link>
          <button className="p-2 hover:bg-gray-100 rounded-full">
            <Image
              src="/search.png"
              alt="검색"
              width={24}
              height={24}
              quality={100}
            />
          </button>
        </div>
      </div>
    </header>
  );
};

export default PreHeader;