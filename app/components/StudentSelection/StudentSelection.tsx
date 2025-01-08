import React, { useState } from 'react';

// 학생 타입 정의
interface Student {
  id: number;
  name: string;
  grade: string;
  class: string;
}

interface StudentSelectionProps {
  formData: {
    students: number[];
    [key: string]: any;  // 다른 formData 속성들을 허용
  };
  setFormData: (data: any) => void;
  onNext: () => void;
  onBack: () => void;
}

export default function StudentSelection({
  formData,
  setFormData,
  onNext,
  onBack
}: StudentSelectionProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  
  // 학생 목록에 타입 적용
  const students: Student[] = [
    // 1학년 1반
    { id: 1101, name: "강수완", grade: "1", class: "1" },
    { id: 1102, name: "고대욱", grade: "1", class: "1" },
    { id: 1103, name: "고미르", grade: "1", class: "1" },
    { id: 1104, name: "김도현", grade: "1", class: "1" },
    { id: 1105, name: "김미래", grade: "1", class: "1" },
    { id: 1106, name: "김범석", grade: "1", class: "1" },
    { id: 1107, name: "김영한", grade: "1", class: "1" },
    { id: 1108, name: "김예은", grade: "1", class: "1" },
    { id: 1109, name: "김유진", grade: "1", class: "1" },
    { id: 1110, name: "김재준", grade: "1", class: "1" },
    { id: 1111, name: "김지현", grade: "1", class: "1" },
    { id: 1112, name: "김태원", grade: "1", class: "1" },
    { id: 1113, name: "김형건", grade: "1", class: "1" },
    { id: 1114, name: "문지환", grade: "1", class: "1" },
    { id: 1115, name: "박민준", grade: "1", class: "1" },
    { id: 1116, name: "부지성", grade: "1", class: "1" },
    { id: 1117, name: "양예솔", grade: "1", class: "1" },
    { id: 1118, name: "이주하", grade: "1", class: "1" },
    { id: 1119, name: "정예찬", grade: "1", class: "1" },
    { id: 1120, name: "조민석", grade: "1", class: "1" },
    { id: 1121, name: "현민서", grade: "1", class: "1" },
    // 1학년 2반
    { id: 1201, name: "고은우", grade: "1", class: "2" },
    { id: 1202, name: "김가현", grade: "1", class: "2" },
    { id: 1203, name: "김동연", grade: "1", class: "2" },
    { id: 1204, name: "김동휘", grade: "1", class: "2" },
    { id: 1205, name: "김라엘", grade: "1", class: "2" },
    { id: 1206, name: "김소진", grade: "1", class: "2" },
    { id: 1207, name: "김승준", grade: "1", class: "2" },
    { id: 1208, name: "문대원", grade: "1", class: "2" },
    { id: 1209, name: "문지원", grade: "1", class: "2" },
    { id: 1210, name: "박서율", grade: "1", class: "2" },
    { id: 1211, name: "박소은", grade: "1", class: "2" },
    { id: 1212, name: "부권준", grade: "1", class: "2" },
    { id: 1213, name: "성준석", grade: "1", class: "2" },
    { id: 1214, name: "손문진", grade: "1", class: "2" },
    { id: 1215, name: "양선홍", grade: "1", class: "2" },
    { id: 1216, name: "정유근", grade: "1", class: "2" },
    { id: 1217, name: "조현준", grade: "1", class: "2" },
    { id: 1218, name: "현유진", grade: "1", class: "2" },
    { id: 1219, name: "현채은", grade: "1", class: "2" },
    { id: 1220, name: "홍은찬", grade: "1", class: "2" },
    // 2학년 1반
    { id: 2101, name: "강서현", grade: "2", class: "1" },
    { id: 2102, name: "고민석", grade: "2", class: "1" },
    { id: 2103, name: "고창환", grade: "2", class: "1" },
    { id: 2104, name: "김나연", grade: "2", class: "1" },
    { id: 2105, name: "김도율", grade: "2", class: "1" },
    { id: 2106, name: "김도훈", grade: "2", class: "1" },
    { id: 2107, name: "김아영", grade: "2", class: "1" },
    { id: 2108, name: "김예림", grade: "2", class: "1" },
    { id: 2109, name: "김채현", grade: "2", class: "1" },
    { id: 2110, name: "박건우", grade: "2", class: "1" },
    { id: 2111, name: "박태현", grade: "2", class: "1" },
    { id: 2112, name: "양승우", grade: "2", class: "1" },
    { id: 2113, name: "오치영", grade: "2", class: "1" },
    { id: 2114, name: "이예찬", grade: "2", class: "1" },
    { id: 2115, name: "이건우", grade: "2", class: "1" },
    { id: 2116, name: "이은상", grade: "2", class: "1" },
    { id: 2117, name: "장지호", grade: "2", class: "1" },
    { id: 2118, name: "정우진", grade: "2", class: "1" },
    { id: 2119, name: "최향아", grade: "2", class: "1" },
    { id: 2120, name: "현승원", grade: "2", class: "1" },
    // 2학년 2반
    { id: 2201, name: "강지윤", grade: "2", class: "2" },
    { id: 2202, name: "김빛나", grade: "2", class: "2" },
    { id: 2203, name: "김승환", grade: "2", class: "2" },
    { id: 2204, name: "김태이", grade: "2", class: "2" },
    { id: 2205, name: "김현상", grade: "2", class: "2" },
    { id: 2206, name: "김효빈", grade: "2", class: "2" },
    { id: 2207, name: "박성빈", grade: "2", class: "2" },
    { id: 2208, name: "변용훈", grade: "2", class: "2" },
    { id: 2209, name: "송민준", grade: "2", class: "2" },
    { id: 2210, name: "양다현", grade: "2", class: "2" },
    { id: 2211, name: "선우준", grade: "2", class: "2" },
    { id: 2212, name: "유서준", grade: "2", class: "2" },
    { id: 2213, name: "이권", grade: "2", class: "2" },
    { id: 2214, name: "이세호", grade: "2", class: "2" },
    { id: 2215, name: "이준이", grade: "2", class: "2" },
    { id: 2216, name: "정하정", grade: "2", class: "2" },
    { id: 2217, name: "최승운", grade: "2", class: "2" },
    { id: 2218, name: "현도훈", grade: "2", class: "2" },
    { id: 2219, name: "현정운", grade: "2", class: "2" }
  ];

  // 검색어를 기반으로 학생 필터링
  const filteredStudents = students.filter(student => 
    student.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    `${student.grade}학년 ${student.class}반`.includes(searchQuery) ||
    String(student.id).includes(searchQuery)
  );

  const handleStudentSelection = (studentId: number) => {
    if (formData.students.includes(studentId)) {
      setFormData({ 
        ...formData, 
        students: formData.students.filter((id: number) => id !== studentId) 
      });
    } else {
      setFormData({ 
        ...formData, 
        students: [...formData.students, studentId] 
      });
    }
  };

  // 선택된 학생 정보 가져오기
  const getSelectedStudents = (): Student[] => {
    return formData.students
      .map(id => students.find(student => student.id === id))
      .filter((student): student is Student => student !== undefined);
  };

  return (
    <div className="bg-white p-6">
      <h2 className="text-2xl font-bold mb-2">참여 학생을 선택해주세요</h2>
      <p className="text-gray-500 mb-8 text-sm">참여할 학생들을 검색하여 선택해주세요</p>
      
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
            placeholder="학생 이름 또는 학년/반으로 검색"
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
              {filteredStudents.length === 0 ? (
                <div className="p-3 text-gray-500 text-center">
                  검색 결과가 없습니다
                </div>
              ) : (
                filteredStudents.map((student) => (
                  <div
                    key={student.id}
                    onClick={() => {
                      handleStudentSelection(student.id);
                      setSearchQuery('');
                      setIsDropdownOpen(false);
                    }}
                    className={`
                      relative cursor-default select-none py-2 pl-4 pr-4
                      ${formData.students.includes(student.id) ? 'bg-blue-50' : ''}
                      ${formData.students.includes(student.id) ? 'text-blue-900' : 'text-gray-900'}
                      hover:bg-blue-100 hover:text-blue-900
                    `}
                  >
                    <div>
                      <span className="font-medium">{student.name}</span>
                      <span className="text-sm text-gray-500 ml-2">
                        {student.id}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </>
        )}
      </div>

      {/* 선택된 학생 목록 */}
      <div className="mt-4">
        <div className="flex flex-wrap gap-2">
          {getSelectedStudents().map((student) => (
            <div 
              key={student.id}
              className="inline-flex items-center bg-blue-50 text-blue-600 rounded-full px-3 py-1"
            >
              <span>{student.name} {student.id}</span>
              <button
                onClick={() => handleStudentSelection(student.id)}
                className="ml-2 text-blue-400 hover:text-blue-600"
              >
                ×
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* 선택된 학생 수 표시 */}
      <div className="text-sm text-gray-500 mt-2 text-right">
        선택된 학생: {formData.students.length}명
      </div>

      {/* 이전/다음 버튼 */}
      <div className="flex gap-3 mt-8">
        <button
          onClick={onBack}
          className="w-full py-3.5 px-4 rounded-xl border border-gray-200 text-gray-700 text-[17px] font-medium hover:bg-gray-50 transition-colors"
        >
          이전으로
        </button>
        <button
          onClick={onNext}
          disabled={formData.students.length === 0}
          className="w-full py-3.5 px-4 rounded-xl bg-blue-500 text-white text-[17px] font-medium hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          다음으로
        </button>
      </div>
    </div>
  );
}