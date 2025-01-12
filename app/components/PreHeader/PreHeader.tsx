'use client';
// 3ECF8E
// 00C573
// 006239
// 128453

import Image from "next/image";
import Link from "next/link";

export default function PreHeader() {
  return (
    <header className="w-full border-b border-gray-200">
      <div className="max-w-6xl mx-auto px-5 sm:px-7 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center">
          <Link href="/" className="flex items-center gap-2">
            <Image
              src="/3dlogo.png"
              alt="로고"
              width={27}
              height={27}
              className="w-8 h-8"
              quality={100}
              priority
            />
            <h1 className="text-[21px] font-extrabold">이디저디</h1>
          </Link>
        </div>
        
        <div className="flex items-center gap-4">
          <Link 
            href="/contact" 
            className="text-gray-600 hover:text-black font-bold text-lg px-3 py-2 rounded-lg hover:bg-gray-100 transition-all duration-180"
          >
            문의하기
          </Link>
          <button 
            className="p-2 hover:bg-gray-100 rounded-full"
            onClick={() => alert('로그인 후 사용가능합니다')}
          >
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
}