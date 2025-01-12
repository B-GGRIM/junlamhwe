import React, { useState } from 'react';

interface TeacherSelectionProps {
  formData: any;
  setFormData: (data: any) => void;
  onSubmit: () => void;
  onBack: () => void;
}

export default function TeacherSelection({
  formData,
  setFormData,
  onSubmit,
  onBack
}: TeacherSelectionProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  // 실제로는 API나 데이터베이스에서 가져올 교사 목록
  const teachers = [
    { id: 1, name: "김민철", subject: "수학" },
    { id: 2, name: "고경석", subject: "물리" },
    { id: 3, name: "김태경", subject: "물리" },
    { id: 4, name: "양은심", subject: "정보" },
    { id: 5, name: "유지호", subject: "역사" },
    { id: 6, name: "이경진", subject: "국어" },
    { id: 7, name: "최정호", subject: "수학" },
    { id: 8, name: "현지수", subject: "국어" },
    { id: 9, name: "박주희", subject: "" },
    { id: 10, name: "이윤우", subject: "" },
    { id: 11, name: "박강희", subject: "" },
    { id: 12, name: "오동율", subject: "수학" },
    { id: 13, name: "최바울", subject: "생명" },
    { id: 14, name: "김진욱", subject: "체육" },
    { id: 15, name: "양원", subject: "국어" },
    { id: 16, name: "한승진", subject: "화학" },
    { id: 17, name: "이경숙", subject: "보건" },
    { id: 18, name: "정지용", subject: "수학" },
    { id: 19, name: "문지섭", subject: "생명" },
    { id: 20, name: "차민서", subject: "화학" },
    { id: 21, name: "강지연", subject: "영어" },
    { id: 22, name: "강신혜", subject: "정보" },
    { id: 23, name: "양동애", subject: "" },
    { id: 24, name: "조현태", subject: "지구" },
    { id: 25, name: "최원태", subject: "지구" }
  ];

  const filteredTeachers = teachers.filter(teacher =>
    teacher.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    teacher.subject.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="bg-white p-6">
      <h1 className="text-2xl font-bold text-[#00C573]">선생님 선택</h1>
      <p className="text-gray-500 mb-8 text-sm">담당할 교사를 검색하여 선택해주세요</p>
      
      {/* 검색 드롭다운 */}
      <div className="relative mt-1">
        <div className="relative">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setIsDropdownOpen(true);
            }}
            onFocus={() => setIsDropdownOpen(true)}
            placeholder="교사 이름 또는 과목으로 검색"
            className="w-full cursor-default rounded-lg bg-white py-4 pl-10 pr-4 text-left border border-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <svg 
            className="absolute left-3 top-4 h-5 w-5 text-gray-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              strokeWidth={2} 
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" 
            />
          </svg>
        </div>

        {isDropdownOpen && (
          <>
            <div 
              className="fixed inset-0"
              style={{ zIndex: 50 }}
              onClick={() => setIsDropdownOpen(false)}
            />
            <div 
              className="absolute mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-50"
            >
              {filteredTeachers.length === 0 ? (
                <div className="p-3 text-gray-500 text-center">
                  검색 결과가 없습니다
                </div>
              ) : (
                filteredTeachers.map((teacher) => (
                  <div
                    key={teacher.id}
                    onClick={() => {
                      setFormData({ ...formData, teacher: teacher.id });
                      setSearchQuery('');
                      setIsDropdownOpen(false);
                    }}
                    className={`
                      relative cursor-default select-none py-2 pl-4 pr-4
                      ${formData.teacher === teacher.id ? 'bg-blue-50' : ''}
                      ${formData.teacher === teacher.id ? 'text-blue-900' : 'text-gray-900'}
                      hover:bg-blue-100 hover:text-blue-900
                    `}
                  >
                    <div>
                      <span className="font-medium">{teacher.name}</span>
                      <span className="text-sm text-gray-500 ml-2">
                        {teacher.subject}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </>
        )}
      </div>

      {/* 선택된 교사 표시 */}
      <div className="mt-4">
        {formData.teacher && (
          <div className="flex flex-wrap gap-2">
            {(() => {
              const selectedTeacher = teachers.find(t => t.id === formData.teacher);
              if (selectedTeacher) {
                return (
                  <div 
                    key={selectedTeacher.id}
                    className="inline-flex items-center bg-blue-50 text-blue-600 rounded-full px-3 py-1"
                  >
                    <span>{selectedTeacher.name} ({selectedTeacher.subject})</span>
                    <button
                      onClick={() => setFormData({ ...formData, teacher: null })}
                      className="ml-2 text-blue-400 hover:text-blue-600"
                    >
                      ×
                    </button>
                  </div>
                );
              }
            })()}
          </div>
        )}
      </div>

      {/* 이전/제출 버튼 */}
      <div className="flex gap-3 mt-8">
        <button
          onClick={onBack}
          className="w-full py-3.5 px-4 rounded-xl border border-gray-200 text-gray-700 text-[17px] font-medium hover:bg-gray-50 transition-colors"
        >
          이전으로
        </button>
        <button
          onClick={onSubmit}
          disabled={!formData.teacher}
          className="w-full py-3.5 px-4 rounded-xl bg-[#3ECF8E] text-white text-[17px] font-medium hover:bg-[#3ECF8E] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          제출하기
        </button>
      </div>
    </div>
  );
}