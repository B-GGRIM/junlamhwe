import { Fragment } from 'react';
import { Listbox, Transition } from '@headlessui/react';
import { ChevronDownIcon } from '@heroicons/react/20/solid';

interface LocationSelectionProps {
  formData: {
    location: string;
    etcDetail?: string;
  };
  setFormData: (data: any) => void;
  onNext: () => void;
  onBack: () => void;
}

export default function LocationSelection({ 
  formData, 
  setFormData, 
  onNext, 
  onBack 
}: LocationSelectionProps) {
  const locationGroups = {
    "교실": [
      { id: "class1-1", name: "1학년 1반" },
      { id: "class1-2", name: "1학년 2반" },
      { id: "class2-1", name: "2학년 1반" },
      { id: "class2-2", name: "2학년 2반" },
      { id: "class3-1", name: "3학년 1반" },
      { id: "class3-2", name: "3학년 2반" },
    ],
    "학습공간": [
      { id: "library", name: "도서관" },
      { id: "library-study", name: "도서관 스터디룸" },
      { id: "multimedia", name: "멀티미디어실" },
      { id: "language", name: "어학실" },
      { id: "meeting", name: "회의실" },
    ],
    "연구동": [
      { id: "physics", name: "물리실험실" },
      { id: "chemistry", name: "화학실험실" },
      { id: "biology", name: "생물실험실" },
      { id: "earth", name: "지구과학실" },
      { id: "math", name: "수학실" },
    ],
    "특별실": [
      { id: "vr", name: "VR체험실" },
      { id: "equipment", name: "전문 기자재실" },
      { id: "music", name: "실용음악부실" },
      { id: "fitness", name: "체력단련실" },
      { id: "imagination", name: "무한상상실" },
      { id: "activity", name: "학생 활동실" },
      { id: "etc", name: "기타" },
    ],
  };

  // 모든 위치를 하나의 배열로 변환
  const allLocations = Object.entries(locationGroups).flatMap(([category, locations]) =>
    locations.map(location => ({
      ...location,
      category
    }))
  );

  return (
    <div className="bg-white p-6">
      <h1 className="text-2xl font-bold text-[#00C573] mb-2">위치 선택</h1>
      <p className="text-gray-500 mb-8 text-sm">특별실을 선택해주세요</p>

      <Listbox 
        value={formData.location} 
        onChange={(value) => {
          setFormData({ 
            ...formData, 
            location: value,
            // 기타가 아닌 항목 선택시 etcDetail 초기화
            etcDetail: value === "기타" ? formData.etcDetail : undefined 
          })
        }}
      >
        <div className="relative mt-1">
          <Listbox.Button className="relative w-full cursor-default rounded-lg bg-white py-4 pl-4 pr-10 text-left border border-gray-200 focus:outline-none focus-visible:border-blue-500 focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-opacity-75 focus-visible:ring-offset-2 focus-visible:ring-offset-blue-300">
            <span className="block truncate">
              {formData.location || '장소를 선택해주세요'}
            </span>
            <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
              <ChevronDownIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
            </span>
          </Listbox.Button>
          <Transition
            as={Fragment}
            leave="transition ease-in duration-100"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <Listbox.Options className="absolute mt-1 max-h-60 w-full overflow-auto rounded-md bg-white py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-50">
              {Object.entries(locationGroups).map(([category, locations]) => (
                <div key={category} className="mb-2 last:mb-0">
                  <div className="px-4 py-2 text-sm font-semibold text-gray-500 bg-gray-50">
                    {category}
                  </div>
                  <div className="py-1">
                    {locations.map((location) => (
                      <Listbox.Option
                        key={location.id}
                        value={location.name}
                        className={({ active, selected }) =>
                          `relative cursor-default select-none py-2 pl-4 pr-4 ${
                            active ? 'bg-blue-100 text-blue-900' : 'text-gray-900'
                          } ${selected ? 'bg-blue-50' : ''}`
                        }
                      >
                        {location.name}
                      </Listbox.Option>
                    ))}
                  </div>
                </div>
              ))}
            </Listbox.Options>
          </Transition>
        </div>
      </Listbox>

      {formData.location === "기타" && (
        <div className="mt-4">
          <label htmlFor="etcDetail" className="block text-sm font-medium text-gray-700 mb-2">
            사용할 장소를 입력해주세요
          </label>
          <input
            type="text"
            id="etcDetail"
            value={formData.etcDetail || ''}
            onChange={(e) => setFormData({ ...formData, etcDetail: e.target.value })}
            className="w-full px-4 py-3 rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="사용할 장소를 입력해주세요"
          />
        </div>
      )}

      <div className="flex gap-3 mt-8">
        <button
          onClick={onBack}
          className="w-full py-3.5 px-4 rounded-xl border border-gray-200 text-gray-700 text-[17px] font-medium hover:bg-gray-50 transition-colors"
        >
          이전으로
        </button>
        <button
          onClick={onNext}
          className="w-full py-3.5 px-4 rounded-xl bg-[#3ECF8E] text-white text-[17px] font-medium hover:bg-[#3ECF8E] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          disabled={!formData.location || (formData.location === "기타" && !formData.etcDetail)}
        >
          다음으로
        </button>
      </div>
    </div>
  );
}