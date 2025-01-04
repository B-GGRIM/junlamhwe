"use client"

import Image from "next/image";
import Link from "next/link";
import { useState, useEffect, useRef } from "react";
import { useRouter } from 'next/navigation';

export default function Header() {
  const router = useRouter();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleLogout = () => {
    document.cookie = 'isLoggedIn=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT';
    sessionStorage.clear();
    router.push('/');
  };

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
              href="/home/specialroom" 
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
        
        <div className="flex items-center relative" ref={menuRef}>
          <button 
            className="p-2 hover:bg-gray-100 rounded-full"
            onClick={() => setIsMenuOpen(!isMenuOpen)}
          >
            <Image
              src="/user.png"
              alt="사용자"
              width={26}
              height={26}
              quality={100}
            />
          </button>

          {isMenuOpen && (
            <div className="absolute right-0 top-full mt-2 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5">
              <div className="py-1">
                <button className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-100 flex items-center">
                  <Image
                    src="/night-mode.png"
                    alt="색상 모드"
                    width={16}
                    height={16}
                    quality={100}
                    className="w-4 min-w-[16px] mr-3"
                  />
                  색상 설정
                </button>
                <button className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-100 flex items-center">
                  <Image
                    src="/bell.png"
                    alt="알림"
                    width={14}
                    height={14}
                    quality={100}
                    className="w-4 min-w-[16px] mr-3"
                  />
                  알림
                </button>
                <button className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-100 flex items-center">
                  <Image
                    src="/cogwheel.png"
                    alt="설정"
                    width={10}
                    height={10}
                    quality={100}
                    className="w-4 min-w-[16px] mr-3"
                  />
                  설정
                </button>
                <button 
                  onClick={handleLogout}
                  className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-red-50 hover:text-red-600 group flex items-center"
                >
                  <Image
                    src="/logout.png"
                    alt="로그아웃"
                    width={14}
                    height={14}
                    quality={100}
                    className="w-4 min-w-[16px] mr-3 group-hover:filter group-hover:invert-[0.4] group-hover:sepia-[1] group-hover:saturate-[7500%] group-hover:hue-rotate-[353deg] group-hover:brightness-[104%] group-hover:contrast-[104%]"
                  />
                  로그아웃
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};